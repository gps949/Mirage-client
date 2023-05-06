//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/dblohm7/wingoes/com"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/safesocket"
	"tailscale.com/smallzstd"
	"tailscale.com/syncs"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/multierr"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/wf"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

var debugMux *http.ServeMux

func init() {
	// Initialize COM process-wide
	comProcessType := com.Service
	if !isWindowsService() {
		comProcessType = com.GUIApp
	}
	if err := com.StartRuntime(comProcessType); err != nil {
		log.Printf("wingoes.com.StartRuntime(%d) failed: %v", comProcessType, err)
	}
}

func init() {
	tstunNew = tstunNewWithWindowsRetries
}

type serverOptions struct {
	VarRoot    string
	LoginFlags controlclient.LoginFlags
}

// 如果是服务调用的子进程
func beWindowsSubprocess() bool {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("无法获取当前执行路径")
	}
	err = windows.SetDllDirectory(filepath.Dir(exePath))
	if err != nil {
		log.Fatalf("无法设置DLL目录")
	}

	if beFirewallKillswitch() { // 处理防火墙设置调用
		return true
	}

	if !args.asServiceSubProc { // 非防火墙设置和子进程
		return false
	}
	dll := windows.NewLazyDLL("wintun.dll")
	if err := dll.Load(); err != nil {
		log.Fatalf("Cannot load wintun.dll for daemon: %v", err)
	}

	logID := args.logid // 传入的logtail ID

	log.SetFlags(0)

	log.Printf("Program starting: v%v: %#v", version.Long(), os.Args)
	log.Printf("subproc mode: logid=%v", logID)
	if err := envknob.ApplyDiskConfigError(); err != nil {
		log.Printf("Error reading environment config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		b := make([]byte, 16)
		for {
			_, err := os.Stdin.Read(b)
			if err == io.EOF {
				// Parent wants us to shut down gracefully.
				log.Printf("subproc received EOF from stdin")
				cancel()
				return
			}
			if err != nil {
				log.Fatalf("stdin err (parent process died): %v", err)
			}
		}
	}()

	sys := new(tsd.System)
	netMon, err := netmon.New(log.Printf)
	if err != nil {
		log.Printf("Could not create netMon: %v", err)
	}
	sys.Set(netMon)

	publicLogID, _ := logid.ParsePublicID(logID)
	err = StartDaemon(ctx, log.Printf, publicLogID, sys)
	if err != nil {
		log.Fatalf("ipnserver: %v", err)
	}
	return true
}

// 供wgengine设置防火墙管理路由调用
func beFirewallKillswitch() bool {
	if !args.asFirewallKillswitch {
		return false
	}

	log.SetFlags(0)
	log.Printf("killswitch subprocess starting, Mirage GUID is %s", args.tunGUID)

	guid, err := windows.GUIDFromString(args.tunGUID)
	if err != nil {
		log.Fatalf("invalid GUID %q: %v", args.tunGUID, err)
	}

	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		log.Fatalf("no interface with GUID %q: %v", guid, err)
	}

	start := time.Now()
	fw, err := wf.New(uint64(luid))
	if err != nil {
		log.Fatalf("failed to enable firewall: %v", err)
	}
	log.Printf("killswitch enabled, took %s", time.Since(start))

	// Note(maisem): when local lan access toggled, tailscaled needs to
	// inform the firewall to let local routes through. The set of routes
	// is passed in via stdin encoded in json.
	dcd := json.NewDecoder(os.Stdin)
	for {
		var routes []netip.Prefix
		if err := dcd.Decode(&routes); err != nil {
			log.Fatalf("parent process died or requested exit, exiting (%v)", err)
		}
		if err := fw.UpdatePermittedRoutes(routes); err != nil {
			log.Fatalf("failed to update routes (%v)", err)
		}
	}
}

// 实际创建daemon IPN
func StartDaemon(ctx context.Context, logf logger.Logf, logID logid.PublicID, sys *tsd.System) error { // lbChn chan *ipnlocal.LocalBackend) {
	ln, err := safesocket.Listen(socketPath)
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	signal.Ignore(syscall.SIGPIPE)
	go func() {
		select {
		case s := <-interrupt:
			logf("miraged got signal %v; shutting down", s)
			cancel()
		case <-ctx.Done():
			// 继续
		}
	}()

	srv := ipnserver.New(logf, logID, sys.NetMon.Get())

	// 先留调试接口
	debugMux = http.NewServeMux()
	debugMux.HandleFunc("/debug/pprof/", pprof.Index)
	debugMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	debugMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	debugMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	debugMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	debugMux.HandleFunc("/debug/ipn", srv.ServeHTMLStatus)

	var lbErr syncs.AtomicValue[error]

	go func() {
		t0 := time.Now()
		lb, err := getLocalBackend(ctx, logf, logID, sys)
		if err == nil {
			logf("got LocalBackend in %v", time.Since(t0).Round(time.Millisecond))
			srv.SetLocalBackend(lb)
			return
		}
		lbErr.Store(err) // before the following cancel
		cancel()         // make srv.Run below complete
	}()

	err = srv.Run(ctx, ln)

	if err != nil && lbErr.Load() != nil {
		return fmt.Errorf("getLocalBackend error: %v", lbErr.Load())
	}

	// Cancelation is not an error: it is the only way to stop ipnserver.
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("ipnserver.Run: %w", err)
	}
	return nil
}

func getLocalBackend(ctx context.Context, logf logger.Logf, logid logid.PublicID, sys *tsd.System) (_ *ipnlocal.LocalBackend, retErr error) {
	if logPol != nil {
		logPol.Logtail.SetNetMon(sys.NetMon.Get())
	}

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	sys.Set(dialer)

	onlyNetstack, err := createEngine(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	if debugMux != nil {
		if ms, ok := sys.MagicSock.GetOK(); ok {
			debugMux.HandleFunc("/debug/magicsock", ms.ServeHTTPDebug)
		}
		go runDebugServer(debugMux, ":"+strconv.FormatInt(debugPort, 10))
	}

	ns, err := newNetstack(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = onlyNetstack
	ns.ProcessSubnets = true

	if onlyNetstack {
		e := sys.Engine.Get()
		dialer.UseNetstackForIP = func(ip netip.Addr) bool {
			_, ok := e.PeerForIP(ip)
			return ok
		}
		dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return ns.DialContextTCP(ctx, dst)
		}
	}

	opts := serverOptions{
		VarRoot: programPath,
	}

	store, err := store.New(logf, filepath.Join(programPath, "miraged.state"))
	if err != nil {
		return nil, fmt.Errorf("store.New: %w", err)
	}
	sys.Set(store)

	lb, err := ipnlocal.NewLocalBackend(logf, logid, sys, opts.LoginFlags)

	if err != nil {
		return nil, fmt.Errorf("ipnlocal.NewLocalBackend: %w", err)
	}
	lb.SetVarRoot(opts.VarRoot)
	if logPol != nil {
		lb.SetLogFlusher(logPol.Logtail.StartFlush)
	}
	if root := lb.TailscaleVarRoot(); root != "" {
		dnsfallback.SetCachePath(filepath.Join(root, "derpmap.cached.json"), logf)
	}
	lb.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})

	if err := ns.Start(lb); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}
	return lb, nil
}

func createEngine(logf logger.Logf, sys *tsd.System) (onlyNetstack bool, err error) {
	var errs []error
	for _, name := range strings.Split(serviceName, ",") {
		logf("wgengine.NewUserspaceEngine(tun %q) ...", name)
		onlyNetstack, err = tryEngine(logf, sys, name)
		if err == nil {
			return onlyNetstack, nil
		}
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", name, err)
		errs = append(errs, err)
	}
	return false, multierr.New(errs...)
}

var tstunNew = tstun.New

func tryEngine(logf logger.Logf, sys *tsd.System, name string) (onlyNetstack bool, err error) {
	conf := wgengine.Config{
		ListenPort:   enginePort,
		NetMon:       sys.NetMon.Get(),
		Dialer:       sys.Dialer.Get(),
		SetSubsystem: sys.Set,
	}
	onlyNetstack = false
	netstackSubnetRouter := onlyNetstack // but mutated later on some platforms
	netns.SetEnabled(true)

	if !onlyNetstack {
		dev, devName, err := tstunNew(logf, name)

		if err != nil {
			tstun.Diagnose(logf, name, err)
			return false, fmt.Errorf("tstun.New(%q): %w", name, err)
		}
		conf.Tun = dev
		if strings.HasPrefix(name, "tap:") {
			conf.IsTAP = true
			e, err := wgengine.NewUserspaceEngine(logf, conf)
			if err != nil {
				return false, err
			}
			sys.Set(e)
			return false, err
		}

		r, err := router.New(logf, dev, sys.NetMon.Get())
		if err != nil {
			dev.Close()
			return false, fmt.Errorf("creating router: %w", err)
		}
		d, err := dns.NewOSConfigurator(logf, devName)
		if err != nil {
			dev.Close()
			r.Close()
			return false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
		}
		conf.DNS = d
		conf.Router = r
		conf.Router = netstack.NewSubnetRouterWrapper(conf.Router)
		netstackSubnetRouter = true
		sys.Set(conf.Router)
	}
	e, err := wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		return false, err
	}
	e = wgengine.NewWatchdog(e)
	sys.Set(e)
	sys.NetstackRouter.Set(netstackSubnetRouter)
	return onlyNetstack, nil
}

func newNetstack(logf logger.Logf, sys *tsd.System) (*netstack.Impl, error) {
	return netstack.Create(logf, sys.Tun.Get(), sys.Engine.Get(), sys.MagicSock.Get(), sys.Dialer.Get(), sys.DNSManager.Get())
}

func tstunNewWithWindowsRetries(logf logger.Logf, tunName string) (_ tun.Device, devName string, _ error) {
	bo := backoff.NewBackoff("tstunNew", logf, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for {
		dev, devName, err := tstun.New(logf, tunName)
		if err == nil {
			return dev, devName, err
		}
		if errors.Is(err, windows.ERROR_DEVICE_NOT_AVAILABLE) || windowsUptime() < 10*time.Minute {
			// Wintun is not installing correctly. Dump the state of NetSetupSvc
			// (which is a user-mode service that must be active for network devices
			// to install) and its dependencies to the log.
			winutil.LogSvcState(logf, "NetSetupSvc")
		}
		bo.BackOff(ctx, err)
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
}

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64Proc = kernel32.NewProc("GetTickCount64")
	procCreateMutex    = kernel32.NewProc("CreateMutexW")
)

func CreateMutex(name string) (uintptr, error) {
	ret, _, err := procCreateMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
	)
	switch int(err.(syscall.Errno)) {
	case 0:
		return ret, nil
	default:
		return ret, err
	}
}

func windowsUptime() time.Duration {
	r, _, _ := getTickCount64Proc.Call()
	return time.Duration(int64(r)) * time.Millisecond
}
