// Package relaystate records recent tunnel observations without authorizing access.
package relaystate

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Leave time for enrollment and rendering within the 15-second online target.
const Interval = 5 * time.Second
const MaxProxies = 1024
const maxBody = 1024 * 1024

var ErrTransport = errors.New("relay observation transport unavailable")
var ErrResponse = errors.New("invalid relay observation response")
var ErrStorage = errors.New("relay observation storage unavailable")

type Observation struct {
	DeviceID  string `json:"device_id"`
	Subdomain string `json:"subdomain"`
}

type Repository interface {
	Observe(context.Context, []Observation) error
}

type Config struct {
	Origin             string
	User               string `json:"-"`
	Password           string `json:"-"`
	Logger             *slog.Logger
	AnomalyActionLimit int
}

type Poller struct {
	endpoint, user, password string
	client                   *http.Client
	repository               Repository
	logger                   *slog.Logger
	interval                 time.Duration
	anomalies                *anomalyWorker
	traffic                  *trafficWorker
}

func New(config Config, repository Repository) (*Poller, error) {
	u, err := url.Parse(config.Origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != config.Origin ||
		len(u.Hostname()) > 253 || strings.Contains(u.Hostname(), "%") || config.Logger == nil || repository == nil {
		return nil, errors.New("relay observation requires a private admin origin, repository and logger")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 || !credential(config.User, 1, 128) || strings.Contains(config.User, ":") || !credential(config.Password, 32, 256) {
		return nil, errors.New("relay observation requires an explicit admin port and valid file-based credentials")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !private(ip) {
		return nil, errors.New("relay admin addresses must be private or loopback")
	}
	u.Path = "/api/proxy/https"
	transport := &http.Transport{Proxy: nil, DialContext: privateDial, DisableCompression: true,
		TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 16 * 1024,
		MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	poller := &Poller{endpoint: u.String(), user: config.User, password: config.Password,
		repository: repository, logger: config.Logger, interval: Interval,
		client: &http.Client{Transport: transport, Timeout: 3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if inspector, ok := repository.(AnomalyRepository); ok {
		limit := config.AnomalyActionLimit
		if limit == 0 {
			limit = 3
		}
		tracker, err := NewAnomalyTracker(time.Now(), limit)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, err
		}
		reader := &Poller{endpoint: poller.endpoint, user: poller.user, password: poller.password,
			client: &http.Client{Transport: transport.Clone(), Timeout: 3 * time.Second,
				CheckRedirect: poller.client.CheckRedirect}}
		poller.anomalies = &anomalyWorker{reader: reader, repository: inspector, tracker: tracker,
			logger: config.Logger, interval: AnomalyInterval, now: time.Now}
	}
	if storage, ok := repository.(TrafficRepository); ok {
		poller.traffic = &trafficWorker{repository: storage, queue: make(chan trafficBatch, 1)}
	}
	return poller, nil
}

func credential(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if char < 33 || char > 126 {
			return false
		}
	}
	return true
}

func private(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && (ip.Unmap().IsPrivate() || ip.Unmap().IsLoopback())
}

// Resolve once, validate every result and dial a literal address. HTTP redirects
// and environment proxies cannot move credentials to another origin.
func privateDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrTransport
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, ErrTransport
		}
	}
	if !allPrivate(addresses) {
		return nil, ErrTransport
	}
	dialer := &net.Dialer{Timeout: time.Second}
	for _, ip := range addresses {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrTransport
}

func allPrivate(addresses []netip.Addr) bool {
	if len(addresses) == 0 || len(addresses) > 16 {
		return false
	}
	for _, address := range addresses {
		if !private(address) {
			return false
		}
	}
	return true
}

func (p *Poller) Poll(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	value, err := p.fetch(ctx)
	if err != nil {
		return err
	}
	if p.traffic != nil {
		p.traffic.offer(trafficBatch{at: value.observedAt, samples: value.traffic, err: value.trafficError})
	}
	storage, cancelStorage := context.WithTimeout(ctx, 2*time.Second)
	defer cancelStorage()
	if err := p.repository.Observe(storage, value.observations); err != nil || storage.Err() != nil {
		return ErrStorage
	}
	return nil
}

func (p *Poller) fetch(ctx context.Context) (snapshot, error) {
	started := time.Now().UTC()
	httpContext, cancelHTTP := context.WithTimeout(ctx, 3*time.Second)
	defer cancelHTTP()
	request, err := http.NewRequestWithContext(httpContext, http.MethodGet, p.endpoint, nil)
	if err != nil {
		return snapshot{}, ErrTransport
	}
	request.SetBasicAuth(p.user, p.password)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	result, err := p.client.Do(request)
	if err != nil {
		return snapshot{}, ErrTransport
	}
	defer result.Body.Close()
	media, parameters, err := mime.ParseMediaType(result.Header.Get("Content-Type"))
	if result.StatusCode != http.StatusOK || err != nil || media != "application/json" || len(result.Header.Values("Content-Type")) != 1 ||
		parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") || len(result.Header.Values("Content-Encoding")) != 0 {
		return snapshot{}, ErrResponse
	}
	value, err := parseSnapshot(result.Body)
	if err != nil || ctx.Err() != nil {
		return snapshot{}, ErrResponse
	}
	value.observedAt = started
	// The relay's generated deployment uses UTC. Do not assign a response that
	// straddles midnight to either daily counter baseline.
	if started.Format("2006-01-02") != time.Now().UTC().Format("2006-01-02") {
		value.traffic, value.trafficError = nil, ErrTrafficResponse
	}
	return value, nil
}

func (p *Poller) Run(ctx context.Context) {
	defer p.client.CloseIdleConnections()
	if p.traffic != nil {
		child, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); p.runTraffic(child) }()
		defer func() {
			stop()
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
			}
		}()
	}
	if p.anomalies != nil {
		child, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); p.anomalies.run(child) }()
		defer func() {
			stop()
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
			}
		}()
	}
	var previous error
	attempt := func() {
		err := p.Poll(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && err != previous {
			code := "storage"
			if errors.Is(err, ErrTransport) {
				code = "transport"
			} else if errors.Is(err, ErrResponse) {
				code = "response"
			}
			p.logger.Warn("Relay observation unavailable", "reason", code)
		} else if err == nil && previous != nil {
			p.logger.Info("Relay observation resumed")
		}
		previous = err
	}
	attempt()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attempt()
		}
	}
}
