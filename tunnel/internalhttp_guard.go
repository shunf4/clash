package tunnel

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// mod: browser-side protection for the clashray send server.
//
// Threat model: local code execution is out of scope, the goal is only to stop
// pages served from an untrusted origin (and DNS rebinding) from driving the send
// endpoint. Two cheap checks are applied:
//  1. POST requests carrying cross-site markers are rejected;
//  2. every request must be addressed to a host that belongs to this clashray
//     deployment (Host allow list), which also blocks rebinding reads of /history.
//
// A CSRF token is deliberately not used: native form posts (which is how
// send.html works) would then depend on javascript being enabled.

var clashraySendHostAllowlist []string

// setClashraySendHostAllowlist is called from RefreshInternalHTTP with the hosts
// that may address the send endpoint.
func setClashraySendHostAllowlist(hosts []string) {
	normalized := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = NormalizeClashrayHost(h)
		if h != "" {
			normalized = append(normalized, h)
		}
	}
	clashraySendHostAllowlist = normalized
}

func clashraySendHostAllowed(r *http.Request) bool {
	if len(clashraySendHostAllowlist) == 0 {
		return true // fail open: nothing configured to check against
	}
	reqHost := NormalizeClashrayHost(r.Host)
	for _, allowed := range clashraySendHostAllowlist {
		if allowed == reqHost {
			return true
		}
		// wildcard entries such as "+.send.example" or "*.send.example" cover the
		// bare domain and every subdomain
		if strings.HasPrefix(allowed, "*.") || strings.HasPrefix(allowed, "+.") {
			suffix := allowed[1:]
			if reqHost == suffix[1:] || strings.HasSuffix(reqHost, suffix) {
				return true
			}
		}
	}
	// Direct IP access (loopback or the configured listen address) keeps working.
	if hostOnly, _, err := net.SplitHostPort(r.Host); err == nil {
		if ip := net.ParseIP(strings.Trim(hostOnly, "[]")); ip != nil {
			for _, allowed := range clashraySendHostAllowlist {
				if ip.String() == allowed || ("["+ip.String()+"]") == allowed {
					return true
				}
			}
			if ip.IsLoopback() {
				return true
			}
		}
	} else if ip := net.ParseIP(strings.Trim(r.Host, "[]")); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func isCrossSitePost(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		return false
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return true
		}
		// same-origin requests carry the Origin of the page; compare host only
		// because the forward/reverse chain may change the scheme.
		return NormalizeClashrayHost(u.Host) != NormalizeClashrayHost(r.Host)
	}
	// No Origin header: browsers always send it on cross-site form POSTs in modern
	// versions, and the add missing-information flag only triggers on the web.
	return false
}

func clashraySendGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !clashraySendHostAllowed(r) {
			log.Warnln("internalHTTP: clashraySend: rejected request for unexpected host %q", r.Host)
			http.Error(w, "unexpected host", http.StatusForbidden)
			return
		}
		if isCrossSitePost(r) {
			log.Warnln("internalHTTP: clashraySend: rejected cross-site %s from origin %q to host %q", r.Method, r.Header.Get("Origin"), r.Host)
			http.Error(w, "cross-site request forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildClashraySendAllowlist collects the hosts the send endpoint is reachable as:
// the configured contact-send-url hosts, every service that resolves to
// INTERNAL-HTTP CLASHRAY-SEND and the local listen address.
func buildClashraySendAllowlist(cfg *Clashray, sendHosts []string) []string {
	hosts := []string{"send.clashray.home.arpa"}
	if cfg != nil {
		for _, p := range cfg.ClashrayNetPublishers {
			if h := strings.TrimPrefix(strings.TrimSpace(p.ContactSendURL), "http://"); h != "" {
				if hh, _, err := net.SplitHostPort(h); err == nil {
					h = hh
				}
				hosts = append(hosts, h)
			}
		}
		if cfg.ClashraySendLocalListenAddr != "" && cfg.ClashraySendLocalListenAddr != "dontListen" {
			hosts = append(hosts, cfg.ClashraySendLocalListenAddr)
		}
	}
	hosts = append(hosts, sendHosts...)
	return hosts
}
