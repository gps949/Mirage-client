// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

type execFunc func(ctx context.Context, args []string) error

type commandInfo struct {
	Name      string
	ShortHelp string
	LongHelp  string
}

var serveHelpCommon = strings.TrimSpace(`
<target> can be a port number (e.g., 3000), a partial URL (e.g., localhost:3000), or a
full URL including a path (e.g., http://localhost:3000/foo, https+insecure://localhost:3000/foo).

EXAMPLES
  - Mount a local web server at 127.0.0.1:3000 in the foreground:
    $ tailscale %s localhost:3000

  - Mount a local web server at 127.0.0.1:3000 in the background:
    $ tailscale %s --bg localhost:3000

For more examples and use cases visit our docs site https://tailscale.com/kb/1247/funnel-serve-use-cases
`)

type serveMode int

const (
	serve serveMode = iota
	funnel
)

type serveType int

const (
	serveTypeHTTPS serveType = iota
	serveTypeHTTP
	serveTypeTCP
	serveTypeTLSTerminatedTCP
)

var infoMap = map[serveMode]commandInfo{
	serve: {
		Name:      "serve",
		ShortHelp: "Serve content and local servers on your tailnet",
		LongHelp: strings.Join([]string{
			"Serve enables you to share a local server securely within your tailnet.\n",
			"To share a local server on the internet, use `tailscale funnel`\n\n",
		}, "\n"),
	},
	funnel: {
		Name:      "funnel",
		ShortHelp: "Serve content and local servers on the internet",
		LongHelp: strings.Join([]string{
			"Funnel enables you to share a local server on the internet using Tailscale.\n",
			"To share only within your tailnet, use `tailscale serve`\n\n",
		}, "\n"),
	},
}

func buildShortUsage(subcmd string) string {
	return strings.Join([]string{
		subcmd + " [flags] <target> [off]",
		subcmd + " status [--json]",
		subcmd + " reset",
	}, "\n  ")
}

// newServeDevCommand returns a new "serve" subcommand using e as its environment.
func newServeDevCommand(e *serveEnv, subcmd serveMode) *ffcli.Command {
	if subcmd != serve && subcmd != funnel {
		log.Fatalf("newServeDevCommand called with unknown subcmd %q", subcmd)
	}

	info := infoMap[subcmd]

	return &ffcli.Command{
		Name:      info.Name,
		ShortHelp: info.ShortHelp,
		ShortUsage: strings.Join([]string{
			fmt.Sprintf("%s <target>", info.Name),
			fmt.Sprintf("%s status [--json]", info.Name),
			fmt.Sprintf("%s reset", info.Name),
		}, "\n  "),
		LongHelp: info.LongHelp + fmt.Sprintf(strings.TrimSpace(serveHelpCommon), info.Name, info.Name),
		Exec:     e.runServeCombined(subcmd),

		FlagSet: e.newFlags("serve-set", func(fs *flag.FlagSet) {
			fs.BoolVar(&e.bg, "bg", false, "run the command in the background")
			fs.StringVar(&e.setPath, "set-path", "", "set a path for a specific target and run in the background")
			fs.StringVar(&e.https, "https", "", "default; HTTPS listener")
			fs.StringVar(&e.http, "http", "", "HTTP listener")
			fs.StringVar(&e.tcp, "tcp", "", "TCP listener")
			fs.StringVar(&e.tlsTerminatedTCP, "tls-terminated-tcp", "", "TLS terminated TCP listener")

		}),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "view current proxy configuration",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:      "reset",
				ShortHelp: "reset current serve/funnel config",
				Exec:      e.runServeReset,
				FlagSet:   e.newFlags("serve-reset", nil),
				UsageFunc: usageFunc,
			},
		},
	}
}

func validateArgs(subcmd serveMode, args []string) error {
	switch len(args) {
	case 0:
		return flag.ErrHelp
	case 1, 2:
		if isLegacyInvocation(subcmd, args) {
			fmt.Fprintf(os.Stderr, "error: the CLI for serve and funnel has changed.")
			fmt.Fprintf(os.Stderr, "Please see https://tailscale.com/kb/1242/tailscale-serve for more information.")
			return errHelp
		}
	default:
		fmt.Fprintf(os.Stderr, "error: invalid number of arguments (%d)", len(args))
		return errHelp
	}
	return nil
}

// runServeCombined is the entry point for the "tailscale {serve,funnel}" commands.
func (e *serveEnv) runServeCombined(subcmd serveMode) execFunc {
	e.subcmd = subcmd

	return func(ctx context.Context, args []string) error {
		if err := validateArgs(subcmd, args); err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("getting client status: %w", err)
		}

		funnel := subcmd == funnel
		if funnel {
			// verify node has funnel capabilities
			if err := e.verifyFunnelEnabled(ctx, st, 443); err != nil {
				return err
			}
		}

		mount, err := cleanURLPath(e.setPath)
		if err != nil {
			return fmt.Errorf("failed to clean the mount point: %w", err)
		}

		if e.setPath != "" {
			// TODO(marwan-at-work): either
			// 1. Warn the user that this is a side effect.
			// 2. Force the user to pass --bg
			// 3. Allow set-path to be in the foreground.
			e.bg = true
		}

		srvType, srvPort, err := srvTypeAndPortFromFlags(e)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
			return errHelp
		}

		sc, err := e.lc.GetServeConfig(ctx)
		if err != nil {
			return fmt.Errorf("error getting serve config: %w", err)
		}

		// nil if no config
		if sc == nil {
			sc = new(ipn.ServeConfig)
		}
		dnsName := strings.TrimSuffix(st.Self.DNSName, ".")

		// set parent serve config to always be persisted
		// at the top level, but a nested config might be
		// the one that gets manipulated depending on
		// foreground or background.
		parentSC := sc

		turnOff := "off" == args[len(args)-1]
		if !turnOff && srvType == serveTypeHTTPS {
			// Running serve with https requires that the tailnet has enabled
			// https cert provisioning. Send users through an interactive flow
			// to enable this if not already done.
			//
			// TODO(sonia,tailscale/corp#10577): The interactive feature flow
			// is behind a control flag. If the tailnet doesn't have the flag
			// on, enableFeatureInteractive will error. For now, we hide that
			// error and maintain the previous behavior (prior to 2023-08-15)
			// of letting them edit the serve config before enabling certs.
			if err := e.enableFeatureInteractive(ctx, "serve", tailcfg.CapabilityHTTPS); err != nil {
				return fmt.Errorf("error enabling https feature: %w", err)
			}
		}

		var watcher *tailscale.IPNBusWatcher
		if !e.bg && !turnOff {
			// if foreground mode, create a WatchIPNBus session
			// and use the nested config for all following operations
			// TODO(marwan-at-work): nested-config validations should happen here or previous to this point.
			watcher, err = e.lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
			if err != nil {
				return err
			}
			defer watcher.Close()
			n, err := watcher.Next()
			if err != nil {
				return err
			}
			if n.SessionID == "" {
				return errors.New("missing SessionID")
			}
			fsc := &ipn.ServeConfig{}
			mak.Set(&sc.Foreground, n.SessionID, fsc)
			sc = fsc
		}

		var msg string
		if turnOff {
			err = e.unsetServe(sc, dnsName, srvType, srvPort, mount)
		} else {
			if err := e.validateConfig(parentSC, srvPort, srvType); err != nil {
				return err
			}
			err = e.setServe(sc, st, dnsName, srvType, srvPort, mount, args[0], funnel)
			msg = e.messageForPort(sc, st, dnsName, srvPort)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
			return errHelp
		}

		if err := e.lc.SetServeConfig(ctx, parentSC); err != nil {
			if tailscale.IsPreconditionsFailedError(err) {
				fmt.Fprintln(os.Stderr, "Another client is changing the serve config; please try again.")
			}
			return err
		}

		if msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}

		if watcher != nil {
			for {
				_, err = watcher.Next()
				if err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
						return nil
					}
					return err
				}
			}
		}

		return nil
	}
}

func (e *serveEnv) validateConfig(sc *ipn.ServeConfig, port uint16, wantServe serveType) error {
	sc, isFg := findConfig(sc, port)
	if sc == nil {
		return nil
	}
	if isFg {
		return errors.New("foreground already exists under this port")
	}
	if !e.bg {
		return errors.New("background serve already exists under this port")
	}
	existingServe := serveFromPortHandler(sc.TCP[port])
	if wantServe != existingServe {
		return fmt.Errorf("want %q but port is already serving %q", wantServe, existingServe)
	}
	return nil
}

func serveFromPortHandler(tcp *ipn.TCPPortHandler) serveType {
	switch {
	case tcp.HTTP:
		return serveTypeHTTP
	case tcp.HTTPS:
		return serveTypeHTTPS
	case tcp.TerminateTLS != "":
		return serveTypeTLSTerminatedTCP
	case tcp.TCPForward != "":
		return serveTypeTCP
	default:
		return -1
	}
}

// findConfig finds a config that contains the given port, which can be
// the top level background config or an inner foreground one. The second
// result is true if it's foreground
func findConfig(sc *ipn.ServeConfig, port uint16) (*ipn.ServeConfig, bool) {
	if sc == nil {
		return nil, false
	}
	if _, ok := sc.TCP[port]; ok {
		return sc, false
	}
	for _, sc := range sc.Foreground {
		if _, ok := sc.TCP[port]; ok {
			return sc, true
		}
	}
	return nil, false
}

func (e *serveEnv) setServe(sc *ipn.ServeConfig, st *ipnstate.Status, dnsName string, srvType serveType, srvPort uint16, mount string, target string, allowFunnel bool) error {
	// update serve config based on the type
	switch srvType {
	case serveTypeHTTPS, serveTypeHTTP:
		useTLS := srvType == serveTypeHTTPS
		err := e.applyWebServe(sc, dnsName, srvPort, useTLS, mount, target)
		if err != nil {
			return fmt.Errorf("failed apply web serve: %w", err)
		}
	case serveTypeTCP, serveTypeTLSTerminatedTCP:
		err := e.applyTCPServe(sc, dnsName, srvType, srvPort, target)
		if err != nil {
			return fmt.Errorf("failed to apply TCP serve: %w", err)
		}
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}

	// update the serve config based on if funnel is enabled
	e.applyFunnel(sc, dnsName, srvPort, allowFunnel)

	return nil
}

// messageForPort returns a message for the given port based on the
// serve config and status.
func (e *serveEnv) messageForPort(sc *ipn.ServeConfig, st *ipnstate.Status, dnsName string, srvPort uint16) string {
	var output strings.Builder

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	if sc.AllowFunnel[hp] == true {
		output.WriteString("Available on the internet:\n")
	} else {
		output.WriteString("Available within your tailnet:\n")
	}

	scheme := "https"
	if sc.IsServingHTTP(srvPort) {
		scheme = "http"
	}

	portPart := ":" + fmt.Sprint(srvPort)
	if scheme == "http" && srvPort == 80 ||
		scheme == "https" && srvPort == 443 {
		portPart = ""
	}

	output.WriteString(fmt.Sprintf("%s://%s%s\n\n", scheme, dnsName, portPart))

	if !e.bg {
		output.WriteString("Press Ctrl+C to exit.")
		return output.String()
	}

	srvTypeAndDesc := func(h *ipn.HTTPHandler) (string, string) {
		switch {
		case h.Path != "":
			return "path", h.Path
		case h.Proxy != "":
			return "proxy", h.Proxy
		case h.Text != "":
			return "text", "\"" + elipticallyTruncate(h.Text, 20) + "\""
		}
		return "", ""
	}

	if sc.Web[hp] != nil {
		var mounts []string

		for k := range sc.Web[hp].Handlers {
			mounts = append(mounts, k)
		}
		sort.Slice(mounts, func(i, j int) bool {
			return len(mounts[i]) < len(mounts[j])
		})
		maxLen := len(mounts[len(mounts)-1])

		for _, m := range mounts {
			h := sc.Web[hp].Handlers[m]
			t, d := srvTypeAndDesc(h)
			output.WriteString(fmt.Sprintf("%s %s%s %-5s %s\n", "|--", m, strings.Repeat(" ", maxLen-len(m)), t, d))
		}
	} else if sc.TCP[srvPort] != nil {
		h := sc.TCP[srvPort]

		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}

		output.WriteString(fmt.Sprintf("|-- tcp://%s (%s)\n", hp, tlsStatus))
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(srvPort)))
			output.WriteString(fmt.Sprintf("|-- tcp://%s\n", ipp))
		}
		output.WriteString(fmt.Sprintf("|--> tcp://%s\n", h.TCPForward))
	}

	output.WriteString("\nServe started and running in the background.\n")
	output.WriteString(fmt.Sprintf("To disable the proxy, run: tailscale %s off", infoMap[e.subcmd].Name))

	return output.String()
}

func (e *serveEnv) applyWebServe(sc *ipn.ServeConfig, dnsName string, srvPort uint16, useTLS bool, mount, target string) error {
	h := new(ipn.HTTPHandler)

	switch {
	case strings.HasPrefix(target, "text:"):
		text := strings.TrimPrefix(target, "text:")
		if text == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case filepath.IsAbs(target):
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return errors.New("path serving is not supported if sandboxed on macOS")
		}

		target = filepath.Clean(target)
		fi, err := os.Stat(target)
		if err != nil {
			return errors.New("invalid path")
		}

		// TODO: need to understand this further
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = target
	default:
		t, err := expandProxyTargetDev(target)
		if err != nil {
			return err
		}
		h.Proxy = t
	}

	// TODO: validation needs to check nested foreground configs
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot serve web; already serving TCP")
	}

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{HTTPS: useTLS, HTTP: !useTLS})

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if _, ok := sc.Web[hp]; !ok {
		mak.Set(&sc.Web, hp, new(ipn.WebServerConfig))
	}
	mak.Set(&sc.Web[hp].Handlers, mount, h)

	// TODO: handle multiple web handlers from foreground mode
	for k, v := range sc.Web[hp].Handlers {
		if v == h {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite example is also handled.
		m1 := strings.TrimSuffix(mount, "/")
		m2 := strings.TrimSuffix(k, "/")
		if m1 == m2 {
			delete(sc.Web[hp].Handlers, k)
		}
	}

	return nil
}

func (e *serveEnv) applyTCPServe(sc *ipn.ServeConfig, dnsName string, srcType serveType, srcPort uint16, target string) error {
	var terminateTLS bool
	switch srcType {
	case serveTypeTCP:
		terminateTLS = false
	case serveTypeTLSTerminatedTCP:
		terminateTLS = true
	default:
		return fmt.Errorf("invalid TCP target %q", target)
	}

	dstURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid TCP target %q: %v", target, err)
	}
	host, dstPortStr, err := net.SplitHostPort(dstURL.Host)
	if err != nil {
		return fmt.Errorf("invalid TCP target %q: %v", target, err)
	}

	switch host {
	case "localhost", "127.0.0.1":
		// ok
	default:
		return fmt.Errorf("invalid TCP target %q, must be one of localhost or 127.0.0.1", target)
	}

	if p, err := strconv.ParseUint(dstPortStr, 10, 16); p == 0 || err != nil {
		return fmt.Errorf("invalid port %q", dstPortStr)
	}

	fwdAddr := "127.0.0.1:" + dstPortStr

	// TODO: needs to account for multiple configs from foreground mode
	if sc.IsServingWeb(srcPort) {
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srcPort)
	}

	mak.Set(&sc.TCP, srcPort, &ipn.TCPPortHandler{TCPForward: fwdAddr})

	if terminateTLS {
		sc.TCP[srcPort].TerminateTLS = dnsName
	}

	return nil
}

func (e *serveEnv) applyFunnel(sc *ipn.ServeConfig, dnsName string, srvPort uint16, allowFunnel bool) {
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	// TODO: Should we return an error? Should not be possible.
	// nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// TODO: should ensure there is no other conflicting funnel
	// TODO: add error handling for if toggling for existing sc
	if allowFunnel {
		mak.Set(&sc.AllowFunnel, hp, true)
	}
}

// unsetServe removes the serve config for the given serve port.
func (e *serveEnv) unsetServe(sc *ipn.ServeConfig, dnsName string, srvType serveType, srvPort uint16, mount string) error {
	switch srvType {
	case serveTypeHTTPS, serveTypeHTTP:
		err := e.removeWebServe(sc, dnsName, srvPort, mount)
		if err != nil {
			return fmt.Errorf("failed to remove web serve: %w", err)
		}
	case serveTypeTCP, serveTypeTLSTerminatedTCP:
		err := e.removeTCPServe(sc, srvPort)
		if err != nil {
			return fmt.Errorf("failed to remove TCP serve: %w", err)
		}
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}

	// TODO(tylersmalley): remove funnel

	return nil
}

func srvTypeAndPortFromFlags(e *serveEnv) (srvType serveType, srvPort uint16, err error) {
	sourceMap := map[serveType]string{
		serveTypeHTTP:             e.http,
		serveTypeHTTPS:            e.https,
		serveTypeTCP:              e.tcp,
		serveTypeTLSTerminatedTCP: e.tlsTerminatedTCP,
	}

	var srcTypeCount int
	var srcValue string

	for k, v := range sourceMap {
		if v != "" {
			srcTypeCount++
			srvType = k
			srcValue = v
		}
	}

	if srcTypeCount > 1 {
		return 0, 0, fmt.Errorf("cannot serve multiple types for a single mount point")
	} else if srcTypeCount == 0 {
		srvType = serveTypeHTTPS
		srcValue = "443"
	}

	srvPort, err = parseServePort(srcValue)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", srcValue, err)
	}

	return srvType, srvPort, nil
}

func isLegacyInvocation(subcmd serveMode, args []string) bool {
	if subcmd == serve && len(args) == 2 {
		prefixes := []string{"http", "https", "tcp", "tls-terminated-tcp"}

		for _, prefix := range prefixes {
			if strings.HasPrefix(args[0], prefix) {
				return true
			}
		}
	}

	return false
}

// removeWebServe removes a web handler from the serve config
// and removes funnel if no remaining mounts exist for the serve port.
// The srvPort argument is the serving port and the mount argument is
// the mount point or registered path to remove.
func (e *serveEnv) removeWebServe(sc *ipn.ServeConfig, dnsName string, srvPort uint16, mount string) error {
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot remove web handler; currently serving TCP")
	}

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if !sc.WebHandlerExists(hp, mount) {
		return errors.New("error: handler does not exist")
	}

	// delete existing handler, then cascade delete if empty
	delete(sc.Web[hp].Handlers, mount)
	if len(sc.Web[hp].Handlers) == 0 {
		delete(sc.Web, hp)
		delete(sc.TCP, srvPort)
	}

	// clear empty maps mostly for testing
	if len(sc.Web) == 0 {
		sc.Web = nil
	}

	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}

	// disable funnel if no remaining mounts exist for the serve port
	if sc.Web == nil && sc.TCP == nil {
		delete(sc.AllowFunnel, hp)
	}

	return nil
}

// removeTCPServe removes the TCP forwarding configuration for the
// given srvPort, or serving port.
func (e *serveEnv) removeTCPServe(sc *ipn.ServeConfig, src uint16) error {
	if sc == nil {
		return nil
	}
	if sc.GetTCPPortHandler(src) == nil {
		return errors.New("error: serve config does not exist")
	}
	if sc.IsServingWeb(src) {
		return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", src)
	}
	delete(sc.TCP, src)
	// clear map mostly for testing
	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}
	return nil
}

// expandProxyTargetDev expands the supported target values to be proxied
// allowing for input values to be a port number, a partial URL, or a full URL
// including a path.
//
// examples:
//   - 3000
//   - localhost:3000
//   - http://localhost:3000
//   - https://localhost:3000
//   - https-insecure://localhost:3000
//   - https-insecure://localhost:3000/foo
func expandProxyTargetDev(target string) (string, error) {
	var (
		scheme = "http"
		host   = "127.0.0.1"
	)

	// support target being a port number
	if port, err := strconv.ParseUint(target, 10, 16); err == nil {
		return fmt.Sprintf("%s://%s:%d", scheme, host, port), nil
	}

	// prepend scheme if not present
	if !strings.Contains(target, "://") {
		target = scheme + "://" + target
	}

	// make sure we can parse the target
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return "", fmt.Errorf("invalid URL %w", err)
	}

	// ensure a supported scheme
	switch u.Scheme {
	case "http", "https", "https+insecure":
	default:
		return "", errors.New("must be a URL starting with http://, https://, or https+insecure://")
	}

	// validate the port
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("invalid port %q", u.Port())
	}

	// validate the host.
	switch u.Hostname() {
	case "localhost", "127.0.0.1":
		u.Host = fmt.Sprintf("%s:%d", host, port)
	default:
		return "", errors.New("only localhost or 127.0.0.1 proxies are currently supported")
	}

	return u.String(), nil
}

// cleanURLPath ensures the path is clean and has a leading "/".
func cleanURLPath(urlPath string) (string, error) {
	if urlPath == "" {
		return "/", nil
	}

	// TODO(tylersmalley) verify still needed with path being a flag
	urlPath = cleanMinGWPathConversionIfNeeded(urlPath)
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}

	c := path.Clean(urlPath)
	if urlPath == c || urlPath == c+"/" {
		return urlPath, nil
	}
	return "", fmt.Errorf("invalid mount point %q", urlPath)
}

func (s serveType) String() string {
	switch s {
	case serveTypeHTTP:
		return "http"
	case serveTypeHTTPS:
		return "https"
	case serveTypeTCP:
		return "tcp"
	case serveTypeTLSTerminatedTCP:
		return "tls-terminated-tcp"
	default:
		return "unknownServeType"
	}
}
