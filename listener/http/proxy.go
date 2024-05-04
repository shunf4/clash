package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"
	_ "unsafe"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/log"
)

//go:linkname registerOnHitEOF net/http.registerOnHitEOF
func registerOnHitEOF(rc io.ReadCloser, fn func())

//go:linkname requestBodyRemains net/http.requestBodyRemains
func requestBodyRemains(rc io.ReadCloser) bool

type ubiConnectFixConn struct {
	urlString string
	net.Conn
	bufferedDataToWrite []byte
	isEndBuffer         bool
}

func (u *ubiConnectFixConn) Write(b []byte) (int, error) {
	// Ubi Connect (uplay) 在使用HTTP代理时需要调整HTTP头的顺序使其大致符合原返回的顺序，否则某些头出现顺序不符合会使其出现“Ubisoft Connect检测到不可恢复性错误，必须关闭”报错（似乎只有Beta版会出现）。
	if u.isEndBuffer {
		return u.Conn.Write(b)
	}
	if u.bufferedDataToWrite == nil {
		u.bufferedDataToWrite = make([]byte, 0)
	}
	prevLen := len(u.bufferedDataToWrite)
	u.bufferedDataToWrite = append(u.bufferedDataToWrite, b...)
	// currLen := len(u.bufferedDataToWrite)
	prevLenMinusThree := prevLen - 3
	if prevLenMinusThree < 0 {
		prevLenMinusThree = 0
	}
	var httpHeaderEndIndex int
	{
		httpHeaderEndRelIndex := bytes.Index(u.bufferedDataToWrite[prevLenMinusThree:], []byte{'\r', '\n', '\r', '\n'})
		if httpHeaderEndRelIndex == -1 {
			httpHeaderEndIndex = -1
		} else {
			httpHeaderEndIndex = prevLenMinusThree + httpHeaderEndRelIndex + 4
		}
	}
	if httpHeaderEndIndex != -1 {
		httpHeaderBytesToManipulate := u.bufferedDataToWrite[0:httpHeaderEndIndex]
		httpBytesRemaining := u.bufferedDataToWrite[httpHeaderEndIndex:len(u.bufferedDataToWrite)]
		httpHeaderBytesAfterProcess := []byte{}

		httpLines := bytes.Split(httpHeaderBytesToManipulate, []byte{'\r', '\n'})
		httpLinesWithPrintedFlag := []*struct {
			TheLine          []byte
			AlreadyProcessed bool
		}{}
		httpLinesMapped := map[string]*struct {
			TheLine          []byte
			AlreadyProcessed bool
		}{}
		for _, l := range httpLines {
			if len(l) == 0 {
				continue
			}
			if bytes.HasPrefix(l, []byte("HTTP/")) {
				log.Infoln("ubi connect (uplay) + http proxy fix: adjusting header order for request [%s ~ %s]...", u.urlString, strings.ToValidUTF8(string(l), "?"))

				httpHeaderBytesAfterProcess = append(httpHeaderBytesAfterProcess, l...)
				httpHeaderBytesAfterProcess = append(httpHeaderBytesAfterProcess, []byte{'\r', '\n'}...)
				continue
			}
			lineSplit := bytes.SplitN(l, []byte{':'}, 2)
			s := struct {
				TheLine          []byte
				AlreadyProcessed bool
			}{
				TheLine:          l,
				AlreadyProcessed: false,
			}
			httpLinesWithPrintedFlag = append(httpLinesWithPrintedFlag, &s)
			if utf8.Valid(lineSplit[0]) {
				httpLinesMapped[strings.ToLower(string(lineSplit[0]))] = &s
			}
		}
		processHeader := func(ps *struct {
			TheLine          []byte
			AlreadyProcessed bool
		}) {
			if ps.AlreadyProcessed {
				return
			}
			httpHeaderBytesAfterProcess = append(httpHeaderBytesAfterProcess, ps.TheLine...)
			httpHeaderBytesAfterProcess = append(httpHeaderBytesAfterProcess, []byte{'\r', '\n'}...)
			ps.AlreadyProcessed = true
		}
		processHeaderWithName := func(hName string) {
			if ps, ok := httpLinesMapped[strings.ToLower(hName)]; ok {
				processHeader(ps)
			}
		}
		processHeaderWithName("Server")
		processHeaderWithName("Content-Length")
		processHeaderWithName("Location")
		processHeaderWithName("Expires")
		processHeaderWithName("Cache-Control")
		processHeaderWithName("Pragma")
		processHeaderWithName("Date")
		processHeaderWithName("Connection")
		for _, ps := range httpLinesWithPrintedFlag {
			processHeader(ps)
		}
		httpHeaderBytesAfterProcess = append(httpHeaderBytesAfterProcess, []byte{'\r', '\n'}...)

		{
			_, err := u.Conn.Write(httpHeaderBytesAfterProcess)
			if err != nil {
				return 0, err
			}
		}
		{
			_, err := u.Conn.Write(httpBytesRemaining)
			if err != nil {
				return 0, err
			}
		}
		u.isEndBuffer = true
		u.bufferedDataToWrite = nil
		return len(b), nil
	} else {
		return len(b), nil
	}
}

func HandleConn(c net.Conn, tunnel C.Tunnel, cache *lru.LruCache[string, bool], additions ...inbound.Addition) {
	client := newClient(c, tunnel, additions...)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peekMutex := sync.Mutex{}

	conn := N.NewBufferedConn(c)

	keepAlive := true
	trusted := cache == nil // disable authenticate if lru is nil

	for keepAlive {
		peekMutex.Lock()
		request, err := ReadRequest(conn.Reader())
		peekMutex.Unlock()
		if err != nil {
			break
		}

		request.RemoteAddr = conn.RemoteAddr().String()

		keepAlive = strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"

		var resp *http.Response

		if !trusted {
			resp = authenticate(request, cache)

			trusted = resp == nil
		}

		if trusted {
			if request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(conn, "HTTP/%d.%d %03d %s\r\n\r\n", request.ProtoMajor, request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					break // close connection
				}

				tunnel.HandleTCPConn(inbound.NewHTTPS(request, conn, additions...))

				return // hijack connection
			}

			host := request.Header.Get("Host")
			if host != "" {
				request.Host = host
			}

			request.RequestURI = ""

			if isUpgradeRequest(request) {
				handleUpgrade(conn, request, tunnel, additions...)

				return // hijack connection
			}

			removeHopByHopHeaders(request.Header)
			removeExtraHTTPHostPort(request)

			if request.URL.Scheme == "" || request.URL.Host == "" {
				resp = responseWith(request, http.StatusBadRequest)
			} else {
				request = request.WithContext(ctx)

				startBackgroundRead := func() {
					go func() {
						peekMutex.Lock()
						defer peekMutex.Unlock()
						_, err := conn.Peek(1)
						if err != nil {
							cancel()
						}
					}()
				}
				if requestBodyRemains(request.Body) {
					registerOnHitEOF(request.Body, startBackgroundRead)
				} else {
					startBackgroundRead()
				}
				resp, err = client.Do(request)
				if err != nil {
					resp = responseWith(request, http.StatusBadGateway)
				}
			}

			removeHopByHopHeaders(resp.Header)
		}

		if keepAlive {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
		}

		resp.Close = !keepAlive

		shouldDoUbiConnectFix := true
		if shouldDoUbiConnectFix && (strings.HasSuffix(request.Host, "ubi.com") || strings.HasSuffix(request.Host, "ubi.com.cn") || strings.HasSuffix(request.Host, "ubisoft.com") || strings.HasSuffix(request.Host, "ubisoft.com.cn") || strings.HasSuffix(request.Host, "ubionline.com.cn")) {
			err = resp.Write(&ubiConnectFixConn{request.URL.String(), conn, nil, false})
		} else {
			err = resp.Write(conn)
		}
		if err != nil {
			break // close connection
		}
	}

	_ = conn.Close()
}

func authenticate(request *http.Request, cache *lru.LruCache[string, bool]) *http.Response {
	authenticator := authStore.Authenticator()
	if inbound.SkipAuthRemoteAddress(request.RemoteAddr) {
		authenticator = nil
	}
	if authenticator != nil {
		credential := parseBasicProxyAuthorization(request)
		if credential == "" {
			resp := responseWith(request, http.StatusProxyAuthRequired)
			resp.Header.Set("Proxy-Authenticate", "Basic")
			return resp
		}

		authed, exist := cache.Get(credential)
		if !exist {
			user, pass, err := decodeBasicProxyAuthorization(credential)
			authed = err == nil && authenticator.Verify(user, pass)
			cache.Set(credential, authed)
		}
		if !authed {
			log.Infoln("Auth failed from %s", request.RemoteAddr)

			return responseWith(request, http.StatusForbidden)
		}
	}

	return nil
}

func responseWith(request *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode) + " (From Clash)",
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     http.Header{},
	}
}
