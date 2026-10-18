package tunnel

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/go-chi/chi/v5/middleware"
)

// mod: helpers for the clashray internal HTTP servers.
//
// These servers live on net.Pipe() connections driven by the tunnel listener, so
// chi's stock middleware.Logger would write straight to stdout and stay invisible
// in the app log panel. chiLogToMihomo forwards the same access information to the
// mihomo log observable instead.

// clashrayHTTPLogSkipPrefixes are read-only endpoints hit on every send page load
// (the history iframe reloads them), logging them at info level would be noise.
var clashrayHTTPLogSkipPrefixes = []string{"/file/"}

var clashrayHTTPLogSkipExact = map[string]bool{
	"/history":        true,
	"/currAsPublisher": true,
}

func chiLogToMihomo(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			elapsed := time.Since(start)

			quiet := clashrayHTTPLogSkipExact[r.URL.Path]
			for _, prefix := range clashrayHTTPLogSkipPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					quiet = true
					break
				}
			}
			if quiet {
				log.Debugln("internalHTTP: %s %s %s -> %d (%s)", name, r.Method, r.URL.Path, ww.Status(), elapsed)
				return
			}
			log.Infoln("internalHTTP: %s %s %s host=%q -> %d (%s)", name, r.Method, r.URL.Path, r.Host, ww.Status(), elapsed)
		})
	}
}

// lookupClashrayHTTPRedirect resolves the redirect target for the given request host.
// Exact match wins; otherwise the normalized host (case, trailing dot, default port,
// IPv6 brackets) is used. That keeps existing map keys working while making
// "host:80" and "host" interchangeable.
func lookupClashrayHTTPRedirect(rHost string) (string, bool) {
	if target, ok := clashrayConfig.ClashrayHTTPRedirectMap[rHost]; ok {
		return target, true
	}
	normalized := NormalizeClashrayHost(rHost)
	for key, target := range clashrayConfig.ClashrayHTTPRedirectMap {
		if NormalizeClashrayHost(stripClashrayRedirectPrefixes(key)) == normalized {
			return target, true
		}
	}
	return "", false
}

func stripClashrayRedirectPrefixes(v string) string {
	v = strings.TrimPrefix(v, "no-hosts:")
	v = strings.TrimPrefix(v, "no-hosts-nor-rule:")
	v = strings.TrimPrefix(v, "auto-added:")
	v = strings.TrimPrefix(v, "no-rule:")
	return v
}

// NormalizeClashrayHost normalizes a host key used by clashray-http-redirect-map so
// that "Example.Home.Arpa:80", "example.home.arpa." and "example.home.arpa" all match:
// lower case, no trailing dot, no default port (80/443), IPv6 brackets removed.
func NormalizeClashrayHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if h, port, err := splitHostPortLoose(host); err != nil {
		// no port, or already a bare IPv6 literal
	} else if port == "" || port == "80" || port == "443" {
		host = h
	} else if strings.Contains(h, ":") {
		// keep IPv6 brackets when a port is attached, otherwise the key would be
		// ambiguous ("[::1]:8080" vs "::1:8080")
		host = "[" + h + "]:" + port
	} else {
		host = h + ":" + port
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	// a bare IPv6 literal containing ':' is not host:port, restore brackets so that
	// net.JoinHostPort style keys stay unambiguous
	if strings.Count(host, ":") > 1 {
		host = "[" + host + "]"
	}
	return host
}

func splitHostPortLoose(host string) (string, string, error) {
	if strings.HasPrefix(host, "[") {
		// [v6] or [v6]:port
		end := strings.Index(host, "]")
		if end < 0 {
			return "", "", errInvalidHost
		}
		inner := host[1:end]
		rest := host[end+1:]
		if rest == "" {
			return inner, "", nil
		}
		if strings.HasPrefix(rest, ":") {
			return inner, rest[1:], nil
		}
		return "", "", errInvalidHost
	}
	if strings.Count(host, ":") == 1 {
		i := strings.Index(host, ":")
		return host[:i], host[i+1:], nil
	}
	// no port, or a bare IPv6 literal
	return host, "", errNoPort
}

var (
	errInvalidHost = errors.New("invalid host")
	errNoPort      = errors.New("no port")
)

// joinURLPaths merges the path configured on the redirect target with the path of
// the incoming request, collapsing duplicated slashes at the junction (and inside
// the result, as requested by the clashray design).
func joinURLPaths(basePath, reqPath string) string {
	if reqPath == "" {
		reqPath = "/"
	}
	if basePath == "" || basePath == "/" {
		return collapseSlashes(ensureLeadingSlash(reqPath))
	}
	joined := strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(reqPath, "/")
	joined = collapseSlashes(joined)
	// keep a single trailing slash if the request asked for a directory-ish path
	if strings.HasSuffix(reqPath, "/") && !strings.HasSuffix(joined, "/") {
		joined += "/"
	}
	return joined
}

func ensureLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func collapseSlashes(p string) string {
	if !strings.Contains(p, "//") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	prevSlash := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// mergeRawQuery merges the query configured on the redirect target with the query
// of the incoming request. The request wins for duplicated keys (values are
// replaced as a whole instead of being appended, so a key never turns into a list).
// When only one side carries a query its exact raw encoding is preserved.
func mergeRawQuery(configRaw, reqRaw string) string {
	if configRaw == "" || reqRaw == "" {
		if reqRaw != "" {
			return reqRaw
		}
		return configRaw
	}
	configValues, err := url.ParseQuery(configRaw)
	if err != nil {
		return reqRaw
	}
	reqValues, err := url.ParseQuery(reqRaw)
	if err != nil {
		return reqRaw
	}
	for k, v := range reqValues {
		configValues[k] = v
	}
	return configValues.Encode()
}
