package route

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

var (
	SwitchProxiesCallback func(sGroup string, sProxy string)
)

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getProxy)
		r.Get("/delay", getProxyDelay)
		r.Put("/", updateProxy)
		r.Delete("/", unfixedProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		proxies := tunnel.Proxies()
		proxy, exist := proxies[name]
		if !exist {
			// mod: resolve proxies coming from proxy providers too, so that
			// /proxies/{name}/delay and /proxies/{name} also work for subscription nodes
			proxy, exist = findProviderProxy(r, name)
		}
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// mod: find a proxy inside the configured proxy providers.
// The reserved "default" provider is skipped: it aggregates every proxy (including
// groups) and would shadow or conflict with the main proxy table.
// An optional ?provider=<name> query narrows the lookup when names collide.
func findProviderProxy(r *http.Request, name string) (C.Proxy, bool) {
	const reservedProviderName = "default"
	providers := tunnel.Providers()
	if wanted := r.URL.Query().Get("provider"); wanted != "" {
		pd, ok := providers[wanted]
		if !ok || wanted == reservedProviderName {
			return nil, false
		}
		for _, p := range pd.Proxies() {
			if p.Name() == name {
				return p, true
			}
		}
		return nil, false
	}

	names := make([]string, 0, len(providers))
	for pn := range providers {
		if pn == reservedProviderName {
			continue
		}
		names = append(names, pn)
	}
	sort.Strings(names)

	var (
		found   C.Proxy
		foundIn []string
	)
	for _, pn := range names {
		for _, p := range providers[pn].Proxies() {
			if p.Name() == name {
				if found == nil {
					found = p
				}
				foundIn = append(foundIn, pn)
			}
		}
	}
	if found == nil {
		return nil, false
	}
	if len(foundIn) > 1 {
		log.Warnln("proxy %q exists in multiple providers %v, using the one from %q; add ?provider=<name> to disambiguate", name, foundIn, foundIn[0])
	}
	return found, true
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	proxies := tunnel.Proxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
	})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	render.JSON(w, r, proxy)
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Name string `json:"name"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if err := selector.Set(req.Name); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(fmt.Sprintf("Selector update error: %s", err.Error())))
		return
	}

	cachefile.Cache().SetSelected(proxy.Name(), req.Name)
	if SwitchProxiesCallback != nil {
		// refresh tray menu
		go SwitchProxiesCallback(proxy.Name(), req.Name)
	}
	render.NoContent(w, r)
}

func getProxyDelay(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	url := query.Get("url")
	urlInConfig := executor.DelayTestUrl
	// if urlInConfig != "" {
	// 	url = urlInConfig
	// }
	if url == "" {
		url = urlInConfig
	}
	if url == "" {
		url = "https://www.googleapis.com/auth/documents"
	}
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](query.Get("expected"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	// mod: one start log line per explicit delay test, the matching finish line
	// is emitted by adapter.Proxy.URLTest (see adapter/delaylog.go)
	_, isGroup := proxy.Adapter().(outboundgroup.ProxyGroup)
	log.Infoln("[DelayTest] request proxy=%q type=%s group=%t url=%q timeout=%dms expected=%q",
		proxy.Name(), proxy.Type().String(), isGroup, url, timeout, expectedStatus.String())

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(timeout))
	defer cancel()
	ctx = adapter.WithDelayTestLog(ctx)

	delay, err := proxy.URLTest(ctx, url, expectedStatus)
	if ctx.Err() != nil {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, ErrRequestTimeout)
		return
	}

	if err != nil || delay == 0 {
		render.Status(r, http.StatusServiceUnavailable)
		if err != nil && delay != 0 {
			render.JSON(w, r, err)
		} else {
			render.JSON(w, r, newError("An error occurred in the delay test"))
		}
		return
	}

	render.JSON(w, r, render.M{
		"delay": delay,
	})
}

func unfixedProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if selectAble, ok := proxy.Adapter().(outboundgroup.SelectAble); ok && proxy.Type() != C.Selector {
		selectAble.ForceSet("")
		cachefile.Cache().SetSelected(proxy.Name(), "")
		render.NoContent(w, r)
		return
	}
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, ErrBadRequest)
}
