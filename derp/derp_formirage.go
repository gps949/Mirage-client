package derp

import (
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/gorilla/mux"
	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlclient"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/singleflight"
)

func (s *Server) createHttpc(dialer *tsdial.Dialer) *http.Client {
	serverURL, err := url.Parse(s.ctrlURL)
	if err != nil {
		s.logf("failed to parse control URL %q: %v", s.ctrlURL, err)
		return nil
	}
	netMon, err := netmon.New(log.Printf)
	if err != nil {
		log.Printf("Could not create netMon: %v", err)
		netMon = nil
	}
	s.netMon = netMon
	dnsCache := &dnscache.Resolver{
		Forward:          dnscache.Get().Forward, // use default cache's forwarder
		UseLastGood:      true,
		LookupIPFallback: dnsfallback.MakeLookupFunc(s.logf, netMon),
		Logf:             s.logf,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = tshttpproxy.ProxyFromEnvironment
	tshttpproxy.SetTransportGetProxyConnectHeader(tr)
	tr.TLSClientConfig = tlsdial.Config(serverURL.Hostname(), tr.TLSClientConfig)
	tr.DialContext = dnscache.Dialer(dialer.SystemDial, dnsCache)
	tr.DialTLSContext = dnscache.TLSDialer(dialer.SystemDial, dnsCache, tr.TLSClientConfig)
	tr.ForceAttemptHTTP2 = true
	// Disable implicit gzip compression; the various
	// handlers (register, map, set-dns, etc) do their own
	// zstd compression per naclbox.
	tr.DisableCompression = true
	return &http.Client{Transport: tr}
}

// cgao6: 用以获取控制器的公钥
func (s *Server) prepareNoiseClient() error {
	keyURL := fmt.Sprintf("%v/key?v=%d", s.ctrlURL, tailcfg.CurrentCapabilityVersion)
	req, err := http.NewRequestWithContext(s.ctx, "GET", keyURL, nil)
	if err != nil {
		return fmt.Errorf("create control key request: %v", err)
	}
	dialer := &tsdial.Dialer{Logf: s.logf}
	httpc := s.createHttpc(dialer)
	res, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("fetch control key: %v", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("fetch control key response: %v", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("fetch control key: %d", res.StatusCode)
	}
	var keys tailcfg.OverTLSPublicKeyResponse
	jsonErr := json.Unmarshal(b, &keys)
	if jsonErr != nil {
		return fmt.Errorf("fetch control key response: %v", jsonErr)
	}
	if !keys.PublicKey.IsZero() {
		httpc.CloseIdleConnections()
	}
	s.ctrlPubkey = keys.PublicKey

	s.dnsCache = &dnscache.Resolver{
		Forward:          dnscache.Get().Forward, // use default cache's forwarder
		UseLastGood:      true,
		LookupIPFallback: dnsfallback.MakeLookupFunc(s.logf, s.netMon),
		Logf:             s.logf,
		NetMon:           s.netMon,
	}
	var sfGroup singleflight.Group[struct{}, *controlclient.NoiseClient]
	s.nc, err, _ = sfGroup.Do(struct{}{}, func() (*controlclient.NoiseClient, error) {
		s.logf("creating new noise client")

		nc, err := controlclient.NewNoiseClient(controlclient.NoiseOpts{
			PrivKey:      s.naviPriKey,
			ServerPubKey: keys.PublicKey,
			ServerURL:    s.ctrlURL,
			Dialer:       dialer,
			DNSCache:     s.dnsCache,
			Logf:         s.logf,
			NetMon:       s.netMon,
			DialPlan:     nil,
		})
		if err != nil {
			return nil, err
		}
		return nc, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func decode(res *http.Response, v any) error {
	defer res.Body.Close()
	msg, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("%d: %v", res.StatusCode, string(msg))
	}
	return json.Unmarshal(msg, v)
}

// 在受管情况下进行初始化
func (s *Server) PrepareManaged(url, id string, naviKey key.MachinePrivate) (err error) {
	s.ctx = context.Background()
	s.ctrlURL = url
	s.derpID = id
	s.naviPriKey = naviKey
	s.trustNodesCache, err = ristretto.NewCache(&ristretto.Config{
		NumCounters:        1000000,
		MaxCost:            100000,
		BufferItems:        64,
		IgnoreInternalCost: true,
	})
	if err != nil {
		return fmt.Errorf("create trustNodesCache: %v", err)
	}
	s.Cronjob = cron.New()
	return s.prepareNoiseClient()
}

type NaviNode struct {
	ID           string `gorm:"primary_key;unique;not null" json:"Name"` //映射到DERPNode的Name
	NaviKey      string `json:"NaviKey"`                                 //记录DERPNode的MachineKey公钥
	NaviRegionID int    `gorm:"not null" json:"RegionID"`                //映射到DERPNode的RegionID
	HostName     string `json:"HostName"`                                //这个不需要独有，但是否必须域名呢？
	//这个不用？ CertName string `json:",omitempty"`
	IPv4        string `json:"IPv4"`        // 不是ipv4地址则失效，为none则禁用ipv4
	IPv6        string `json:"IPv6"`        // 不是ipv6地址则失效，为none则禁用ipv6
	NoSTUN      bool   `json:"NoSTUN"`      //禁用STUN
	STUNPort    int    `json:"STUNPort"`    //0代表3478，-1代表禁用
	NoDERP      bool   `json:"NoDERP"`      //禁用DERP
	DERPPort    int    `json:"DERPPort"`    //0代表443
	DNSProvider string `json:"DNSProvider"` //DNS服务商
	DNSID       string `json:"DNSID"`       //DNS服务商的ID
	DNSKey      string `json:"DNSKey"`      //DNS服务商的Key
	Arch        string `json:"Arch"`        //所在环境架构，x86_64或aarch64
}
type RegisterResponse struct {
	NaviInfo   NaviNode
	TrustNodes []string `json:"TrustNodes"`
	Timestamp  *time.Time
}

func (s *Server) TryLogin() (NaviNode, error) {
	request := tailcfg.RegisterRequest{}
	request.Auth.Provider = "Mirage"
	request.Auth.LoginName = s.derpID
	url := fmt.Sprintf("%s/machine/register", s.ctrlURL)
	url = strings.Replace(url, "http:", "https:", 1)
	bodyData, err := json.Marshal(request)
	if err != nil {
		return NaviNode{}, fmt.Errorf("register request: %w", err)
	}
	req, err := http.NewRequestWithContext(s.ctx, "POST", url, bytes.NewReader(bodyData))
	if err != nil {
		return NaviNode{}, fmt.Errorf("register request: %w", err)
	}

	res, err := s.nc.Do(req)
	if err != nil {
		return NaviNode{}, fmt.Errorf("register request: %w", err)
	}

	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return NaviNode{}, fmt.Errorf("register request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	resp := RegisterResponse{}
	if err := decode(res, &resp); err != nil {
		s.logf("error decoding RegisterResponse")
		return NaviNode{}, fmt.Errorf("register request: %v", err)
	}

	s.trustNodesCache.Clear()
	s.trustNodesCache.SetWithTTL("seqnum", 0, 1, 0)
	for _, nkey := range resp.TrustNodes {
		s.trustNodesCache.SetWithTTL(nkey, struct{}{}, 1, 0)
	}
	s.logf("register response: %v", resp)

	return resp.NaviInfo, nil
}

func (s *Server) UpdateNaviInfo(
	naviInfo NaviNode,
	hostname, addr, setIPv4, setIPv6, dnsProvider, dnsID, dnsKey *string,
	stunPort *int,
	runDERP, runSTUN *bool,
) error {
	*hostname = naviInfo.HostName
	if !naviInfo.NoDERP {
		*addr = ":" + strconv.Itoa(naviInfo.DERPPort)
	} else {
		*runDERP = false
	}
	if !naviInfo.NoSTUN {
		*stunPort = naviInfo.STUNPort
	} else {
		*runSTUN = false
	}
	*setIPv4 = naviInfo.IPv4
	*setIPv6 = naviInfo.IPv6
	*dnsProvider = naviInfo.DNSProvider
	*dnsID = naviInfo.DNSID
	*dnsKey = naviInfo.DNSKey
	return nil
}

type PullNodesListResponse struct {
	TrustNodes []string   `json:"TrustNodes"`
	Timestamp  *time.Time `json:"Timestamp"`
}

func (s *Server) PullNodesList() error {
	request := tailcfg.MapRequest{}
	request.Hostinfo = &tailcfg.Hostinfo{
		FrontendLogID: "MirageNavi",
		BackendLogID:  s.derpID,
	}
	url := fmt.Sprintf("%s/navi/nodes", s.ctrlURL)
	url = strings.Replace(url, "http:", "https:", 1)
	bodyData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("map request: %w", err)
	}
	req, err := http.NewRequestWithContext(s.ctx, "POST", url, bytes.NewReader(bodyData))
	if err != nil {
		return fmt.Errorf("map request: %w", err)
	}
	res, err := s.nc.Do(req)
	if err != nil {
		return fmt.Errorf("map request: %w", err)
	}
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("map request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}

	resp := PullNodesListResponse{}
	if err := decode(res, &resp); err != nil {
		s.logf("error decoding TrustNodeList: %v", err)
		return fmt.Errorf("map request: %v", err)
	}
	s.logf("map response: %v", resp)

	s.trustNodesCache.Clear()
	s.trustNodesCache.SetWithTTL("seqnum", 0, 1, 0)
	for _, nkey := range resp.TrustNodes {
		s.trustNodesCache.SetWithTTL(nkey, struct{}{}, 1, 0)
	}

	return nil
}

const (
	noContentChallengeHeader = "X-Tailscale-Challenge"
	noContentResponseHeader  = "X-Tailscale-Response"
)

func isChallengeChar(c rune) bool {
	// Semi-randomly chosen as a limited set of valid characters
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
		('0' <= c && c <= '9') ||
		c == '.' || c == '-' || c == '_'
}
func serveNoContent(w http.ResponseWriter, r *http.Request) {
	if challenge := r.Header.Get(noContentChallengeHeader); challenge != "" {
		badChar := strings.IndexFunc(challenge, func(r rune) bool {
			return !isChallengeChar(r)
		}) != -1
		if len(challenge) <= 64 && !badChar {
			w.Header().Set(noContentResponseHeader, "response "+challenge)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type ts2021App struct {
	navi *Server
	conn *controlbase.Conn
}

func (s *Server) NoiseUpgradeHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	log.Trace().Caller().Msg("noise upgrade handler for controlserver " + r.RemoteAddr)
	upgrade := r.Header.Get("Upgrade")
	if upgrade == "" {
		// This probably means that the user is running Headscale behind an
		// improperly configured reverse proxy. TS2021 requires WebSockets to
		// be passed to Headscale. Let's give them a hint.
		log.Warn().
			Caller().
			Msg("No Upgrade header in TS2021 request. If headscale is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	noiseConn, err := controlhttp.AcceptHTTP(r.Context(), w, r, s.naviPriKey, nil)
	if err != nil {
		log.Error().Err(err).Msg("noise upgrade failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ts2021App := ts2021App{
		navi: s,
		conn: noiseConn,
	}

	router := mux.NewRouter()
	router.Use(ts2021App.NoiseAuthMiddleware)
	router.HandleFunc("/ctrl/nodes", ts2021App.NoiseNodeChangeHandler).
		Methods(http.MethodPost)
	router.Handle("/ctrl/vars", expvar.Handler())
	router.Handle("/generate_204", http.HandlerFunc(serveNoContent))

	server := http.Server{
		ReadTimeout: 30 * time.Second,
	}
	server.Handler = h2c.NewHandler(router, &http2.Server{})
	err = server.Serve(netutil.NewOneConnListener(noiseConn, nil))
	if err != nil {
		log.Trace().Caller().Err(err).Msg("The HTTP2 server was closed")
	}
}

func (t *ts2021App) NoiseAuthMiddleware(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Trace().Caller().Msg("noise auth middleware for controlserver " + r.RemoteAddr)

		if t.conn.Peer() != t.navi.ctrlPubkey {
			log.Error().Msg("noise auth failed")
			http.Error(w, "noise auth failed", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type NodesChange struct {
	SeqNum     int
	AddNode    string
	RemoveNode string
}

func (t *ts2021App) NoiseNodeChangeHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	log.Trace().Caller().Msg("noise node change handler for controlserver " + r.RemoteAddr)

	var nodesChange NodesChange
	err := json.NewDecoder(r.Body).Decode(&nodesChange)
	if err != nil {
		log.Error().Err(err).Msg("error decoding node change")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Trace().Caller().Msgf("node change: %+v", nodesChange)

	sq, ok := t.navi.trustNodesCache.Get("seqnum")
	if !ok {
		log.Error().Msg("seqnum not found")
		http.Error(w, "seqnum not found", http.StatusInternalServerError)
		return
	}
	seqnum, ok := sq.(int)
	if !ok {
		log.Error().Msg("seqnum not int")
		http.Error(w, "seqnum not int", http.StatusInternalServerError)
		return
	}
	if nodesChange.SeqNum != seqnum+1 {
		log.Warn().Msg("seqnum not match! Need to pull nodes list again ")
		err := t.navi.PullNodesList()
		if err != nil {
			log.Error().Err(err).Msg("error pull nodes list")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	t.navi.trustNodesCache.SetWithTTL("seqnum", nodesChange.SeqNum, 1, 0)
	if nodesChange.AddNode != "" {
		t.navi.trustNodesCache.SetWithTTL(nodesChange.AddNode, struct{}{}, 1, 0)
	}
	if nodesChange.RemoveNode != "" {
		t.navi.trustNodesCache.Del(nodesChange.RemoveNode)
	}
}
