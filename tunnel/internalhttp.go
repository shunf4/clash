package tunnel

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aohorodnyk/mimeheader"
	"github.com/flytam/filenamify"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/common/observable"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var (
	internalHTTPClashraySend         *chi.Mux
	internalHTTPClashrayHTTPRedirect *chi.Mux
	internalHTTPClashrayTest         *chi.Mux
	internalHTTPMutex                sync.Mutex
	clashraySendHistoryMutex         sync.Mutex
	clashraySendTextMutex            sync.Mutex

	clashraySendCh         = make(chan ClashraySendReceiveData)
	clashraySendObservable = observable.NewObservable[ClashraySendReceiveData](clashraySendCh)

	clashCurrRawConfigBytes []byte
)

//go:embed send.html
var sendHTMLBytes []byte

//go:embed sendHistory.html
var historyHTMLBytes []byte

type historyData struct {
	Timestamp string
	SendType  string
	Summary   string
	Sender    string
	FileName  string
	FileSize  uint64
}

type ClashraySendReceiveData struct {
	Timestamp       string
	SendType        string
	Summary         string
	InstantCopyText string
	Sender          string
	FileName        string
	FileSize        uint64
	FilePath        string
}

// immitating log.go
func ClashraySendSubscribe() observable.Subscription[ClashraySendReceiveData] {
	sub, _ := clashraySendObservable.Subscribe()
	return sub
}

func ClashraySendUnsubscribe(sub observable.Subscription[ClashraySendReceiveData]) {
	clashraySendObservable.UnSubscribe(sub)
}

func SaveClashCurrRawConfig(clashCurrRawConfigBytes_ []byte, err error) {
	if err != nil {
		log.Warnln("SaveClashCurrRawConfig: has error: %v", err)
	}
	clashCurrRawConfigBytes = clashCurrRawConfigBytes_
}

func neuter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}

		if strings.HasSuffix(strings.ToLower(r.URL.Path), "clashcurrrawconfig.yaml") {
			http.NotFound(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func byteCountIEC(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

func RefreshInternalHTTP(clashrayConfig *Clashray) {
	internalHTTPMutex.Lock()
	defer internalHTTPMutex.Unlock()

	sendHTMLTmpl, err := template.New("send").Parse(string(sendHTMLBytes))
	if err != nil {
		panic(err)
	}

	if runtime.GOOS == "android" {
		os.MkdirAll("/data/data/com.github.metacubex.clash.shunf4mod.meta/cache", os.FileMode(0o750))
		os.Setenv("TMPDIR", "/data/data/com.github.metacubex.clash.shunf4mod.meta/cache")
	}

	historyHTMLTmpl, err := template.New("history").Funcs(template.FuncMap{
		"ByteCountIEC": byteCountIEC,
		"URLEncode":    func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") },
		"isPicture": func(d historyData) bool {
			fileNameLower := strings.ToLower(d.FileName)
			return d.SendType == "file" && (strings.HasSuffix(fileNameLower, ".bmp") ||
				strings.HasSuffix(fileNameLower, ".png") ||
				strings.HasSuffix(fileNameLower, ".jpg") ||
				strings.HasSuffix(fileNameLower, ".jpeg") ||
				strings.HasSuffix(fileNameLower, ".webp") ||
				strings.HasSuffix(fileNameLower, ".apng") ||
				strings.HasSuffix(fileNameLower, ".avif") ||
				strings.HasSuffix(fileNameLower, ".gif") ||
				strings.HasSuffix(fileNameLower, ".svg") ||
				strings.HasSuffix(fileNameLower, ".tif") ||
				strings.HasSuffix(fileNameLower, ".tiff"))
		},
	}).Parse(string(historyHTMLBytes))
	if err != nil {
		panic(err)
	}

	if clashrayConfig.ClashraySendHistoryMaxSize == 0 {
		clashrayConfig.ClashraySendHistoryMaxSize = 60
	}

	if clashrayConfig.ClashraySendHistoryMaxSize >= math.MaxInt32 {
		clashrayConfig.ClashraySendHistoryMaxSize = math.MaxInt32 - 1
	}

	if clashrayConfig.ClashraySendDir != "" {
		os.MkdirAll(clashrayConfig.ClashraySendDir, os.FileMode(0o750))

		if len(clashCurrRawConfigBytes) > 0 {
			os.WriteFile(filepath.Join(clashrayConfig.ClashraySendDir, "ClashCurrRawConfig.yaml"), clashCurrRawConfigBytes, os.FileMode(0o640))
		}

		hf, err := os.OpenFile(filepath.Join(clashrayConfig.ClashraySendDir, "history.json"), os.O_CREATE, os.FileMode(0o640))
		if err != nil {

		} else {
			hf.Close()
		}

		internalHTTPClashraySend = chi.NewRouter()
		internalHTTPClashraySend.Use(middleware.Logger)

		internalHTTPClashraySend.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			sendHTMLTmpl.Execute(w, map[string]any{
				"ClashraySendPublisherName": clashrayConfig.ClashrayNetCurrAsPublisher,
			})
		})

		saveHistory := func(sendType string, summary string, sender string, fileName string, fileSize uint64, sendTime time.Time) error {
			clashraySendHistoryMutex.Lock()
			defer clashraySendHistoryMutex.Unlock()

			historyJsonBytes, err := os.ReadFile(filepath.Join(clashrayConfig.ClashraySendDir, "history.json"))
			var historyList []historyData
			if err != nil {
				historyList = make([]historyData, 0)
			} else {
				err = json.Unmarshal(historyJsonBytes, &historyList)
				if err != nil {
					historyList = make([]historyData, 0)
				}
			}

			if len(historyList) >= int(clashrayConfig.ClashraySendHistoryMaxSize) {
				historyList = historyList[:int(clashrayConfig.ClashraySendHistoryMaxSize)-1]
			}
			historyList = append([]historyData{
				{
					Timestamp: sendTime.Format("2006-01-02 15:04:05 Z07:00"),
					SendType:  sendType,
					Summary:   summary,
					Sender:    sender,
					FileName:  fileName,
					FileSize:  fileSize,
				},
			}, historyList...)
			historyJsonBytesAfterInsert, err := json.Marshal(historyList)
			if err != nil {
				return fmt.Errorf("json marshal error: %w", err)
			}
			err = os.WriteFile(filepath.Join(clashrayConfig.ClashraySendDir, "history.json"), historyJsonBytesAfterInsert, os.FileMode(0o640))
			if err != nil {
				return fmt.Errorf("write history.json error: %w", err)
			}
			return nil
		}

		saveText := func(textBytes []byte, sender string) error {
			clashraySendTextMutex.Lock()
			defer clashraySendTextMutex.Unlock()

			if len(textBytes) > 1*1024*1024*1024 {
				return fmt.Errorf("text too big")
			}

			err := os.WriteFile(filepath.Join(clashrayConfig.ClashraySendDir, "text.txt"), textBytes, 0o640)

			if err != nil {
				return err
			}

			thisUUID, err := uuid.NewV4()
			if err != nil {
				return fmt.Errorf("generating uuid: %w", err)
			}

			fileName := "text-" + thisUUID.String() + ".txt"

			err = os.WriteFile(filepath.Join(clashrayConfig.ClashraySendDir, fileName), textBytes, 0o640)

			if err != nil {
				return fmt.Errorf("saving file: %w", err)
			}

			textString := string(textBytes)
			runes := []rune(textString)
			ellipsis := "..."
			runeCut := 400
			if runeCut > len(runes) {
				ellipsis = ""
				runeCut = len(runes)
			}
			now := time.Now()
			summary := string(runes[:runeCut]) + ellipsis
			err = saveHistory("text", summary, sender, fileName, uint64(len(textBytes)), now)
			if err != nil {
				return fmt.Errorf("saving history: %w", err)
			}

			instantCopyText := ""
			if len(runes) < 2*1024*1024 && len(textBytes) < 7*1024*1024 { // about 3~5MiBytes of text
				instantCopyText = textString
			}

			chSummary := summary
			if ellipsis != "" {
				chSummary += " (" + byteCountIEC(uint64(len(textBytes))) + ")"
			}
			if sender != "" {
				chSummary += " sent by " + sender
			}

			clashraySendCh <- ClashraySendReceiveData{
				Timestamp:       now.Format("2006-01-02 15:04:05 Z07:00"),
				SendType:        "text",
				Summary:         chSummary,
				InstantCopyText: instantCopyText,
				Sender:          sender,
				FileName:        fileName,
				FileSize:        uint64(len(textBytes)),
				FilePath:        filepath.Join(clashrayConfig.ClashraySendDir, fileName),
			}

			return nil
		}

		internalHTTPClashraySend.Post("/", func(w http.ResponseWriter, r *http.Request) {
			ct := r.Header.Get("Content-Type")
			if ct == "" {
				ct = "text/plain"
			}
			ct, _, err := mime.ParseMediaType(ct)
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Could not media type: %v", err)
				return
			}

			sender := r.Header.Get("Clashray-Sender")
			sendTime := time.Now()

			switch {
			case ct == "text/plain" || ct == "application/octet-stream":
				textBytes, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024*1024))
				if err != nil {
					internalHttpError(w, r, http.StatusBadRequest, "Could not process text", err)
					return
				}
				err = saveText(textBytes, sender)
				if err != nil {
					internalHttpError(w, r, http.StatusBadRequest, "Error saving text", err)
					return
				}
				render.PlainText(w, r, "OK")
				return
			case ct == "application/x-www-form-urlencoded":
				err = r.ParseForm()
				if err != nil {
					internalHttpError(w, r, http.StatusBadRequest, "Could not parse form", err)
					return
				}
				if r.FormValue("sender") != "" {
					sender = r.FormValue("sender")
				}
				err = saveText([]byte(r.FormValue("text")), sender)
				if err != nil {
					internalHttpError(w, r, http.StatusBadRequest, "Error saving text", err)
					return
				}
				render.PlainText(w, r, "OK")
				return
			}

			err = r.ParseMultipartForm(20 * 1024 * 1024)
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Could not parse multipart form", err)
				return
			}
			if r.FormValue("sender") != "" {
				sender = r.FormValue("sender")
			}
			if r.FormValue("text") != "" {
				err = saveText([]byte(r.FormValue("text")), sender)
				if err != nil {
					internalHttpError(w, r, http.StatusBadRequest, "Error saving text", err)
					return
				}
				render.PlainText(w, r, "OK")
				return
			}
			file, fileHeader, err := r.FormFile("file")
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Invalid file", err)
				return
			}
			defer file.Close()
			if fileHeader.Size > 3*1024*1024*1024 {
				internalHttpError(w, r, http.StatusBadRequest, "File is too big")
				return
			}
			safeName, err := filenamify.Filenamify(fileHeader.Filename, filenamify.Options{
				Replacement: "_",
				MaxLength:   60,
			})
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during filename process", err)
				return
			}
			if !filepath.IsLocal(safeName) {
				safeName = filepath.Base(safeName) + "_"
			}
			if _, err := os.Stat(filepath.Join(clashrayConfig.ClashraySendDir, safeName)); err == nil {
				safeNameExt := filepath.Ext(safeName)
				safeNameWithoutExt := strings.TrimSuffix(safeName, safeNameExt)
				safeName = safeNameWithoutExt + "_" + sendTime.Format("2006-01-02T15_04_05Z070000")
				if safeNameExt != "" {
					safeName += safeNameExt
				}
			}

			outF, err := os.Create(filepath.Join(clashrayConfig.ClashraySendDir, safeName))
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during file creation", err)
				return
			}
			defer outF.Close()
			fileActualSize, err := io.Copy(outF, file)
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during file write", err)
				return
			}
			err = saveHistory("file", "File: "+safeName, sender, safeName, uint64(fileActualSize), sendTime)
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during updating history", err)
				return
			}

			chSummary := "File: " + safeName
			chSummary += " (" + byteCountIEC(uint64(fileActualSize)) + ")"
			if sender != "" {
				chSummary += " sent by " + sender
			}

			clashraySendCh <- ClashraySendReceiveData{
				Timestamp:       sendTime.Format("2006-01-02 15:04:05 Z07:00"),
				SendType:        "file",
				Summary:         chSummary,
				InstantCopyText: "",
				Sender:          sender,
				FileName:        safeName,
				FileSize:        uint64(uint64(fileActualSize)),
				FilePath:        filepath.Join(clashrayConfig.ClashraySendDir, safeName),
			}

			render.PlainText(w, r, "OK")
		})

		internalHTTPClashraySend.Get("/text", func(w http.ResponseWriter, r *http.Request) {
			atRaw := r.Header.Get("Accept")
			at := mimeheader.ParseAcceptHeader(atRaw)
			f, err := os.Open(filepath.Join(clashrayConfig.ClashraySendDir, "text.txt"))
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during file open", err)
				return
			}
			defer f.Close()
			if at.Match("text/plain") {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, err = io.Copy(w, io.LimitReader(f, 1*1024*1024*1024))
				if err != nil {
					internalHttpError(w, r, http.StatusInternalServerError, "Error during stream copy", err)
					return
				}
				return
			}
			// if at.Match("application/json") {
			// 	w.Header().Set("Content-Type", "application/json; charset=utf-8")
			// 	fileBytes, err := io.ReadAll(io.LimitReader(f, 1*1024*1024*1024))
			// 	if err != nil {
			// 		internalHttpError(w, r, http.StatusInternalServerError, "Error during file read", err)
			// 		return
			// 	}
			// 	render.JSON(w, r, map[string]interface{}{
			// 		"data": fileBytes,
			// 	})
			// 	return
			// }
			internalHttpError(w, r, http.StatusBadRequest, "No proper Accept type received")
		})

		internalHTTPClashraySend.Post("/text", func(w http.ResponseWriter, r *http.Request) {
			textBytes, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024*1024))
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Could not process text", err)
				return
			}
			err = saveText(textBytes, r.Header.Get("Clashray-Sender"))
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Error saving text", err)
				return
			}
			render.PlainText(w, r, "OK")
		})

		internalHTTPClashraySend.Get("/history", func(w http.ResponseWriter, r *http.Request) {
			atRaw := r.Header.Get("Accept")
			at := mimeheader.ParseAcceptHeader(atRaw)

			clashraySendHistoryMutex.Lock()
			defer clashraySendHistoryMutex.Unlock()

			historyJsonBytes, err := os.ReadFile(filepath.Join(clashrayConfig.ClashraySendDir, "history.json"))
			var historyList []historyData
			if err != nil {
				historyList = make([]historyData, 0)
			} else {
				err = json.Unmarshal(historyJsonBytes, &historyList)
				if err != nil {
					historyList = make([]historyData, 0)
				}
			}

			if at.Match("text/html") || at.Match("application/xhtml+xml") {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				historyHTMLTmpl.Execute(w, map[string]any{
					"ClashraySendPublisherName": clashrayConfig.ClashrayNetCurrAsPublisher,
					"HistoryList":               historyList,
				})
				return
			}
			if at.Match("application/json") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err = io.Copy(w, bytes.NewBuffer(historyJsonBytes))
				if err != nil {
					internalHttpError(w, r, http.StatusInternalServerError, "Error during stream copy", err)
					return
				}
				return
			}
			if at.Match("text/plain") {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, err = io.Copy(w, bytes.NewBuffer(historyJsonBytes))
				if err != nil {
					internalHttpError(w, r, http.StatusInternalServerError, "Error during stream copy", err)
					return
				}
				return
			}

			internalHttpError(w, r, http.StatusBadRequest, "No proper Accept type received")
		})

		internalHTTPClashraySend.Get("/file/*", neuter(http.StripPrefix("/file/", http.FileServer(http.Dir(clashrayConfig.ClashraySendDir)))).ServeHTTP)
	} else {
		internalHTTPClashraySend = chi.NewRouter()
		internalHTTPClashraySend.Use(middleware.Logger)
		internalHTTPClashraySend.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			internalHttpError(w, r, http.StatusForbidden, "Clashray Send Not Available")
		}))
	}

	internalHTTPClashrayHTTPRedirect = chi.NewRouter()
	internalHTTPClashrayHTTPRedirect.Use(middleware.Logger)
	internalHTTPClashrayHTTPRedirect.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		// From https://github.com/go-chi/hostrouter/blob/master/hostrouter.go
		parseForwarded := func(forwarded string) (addr, proto, host string) {
			if forwarded == "" {
				return
			}
			for _, forwardedPair := range strings.Split(forwarded, ";") {
				if tv := strings.SplitN(forwardedPair, "=", 2); len(tv) == 2 {
					token, value := tv[0], tv[1]
					token = strings.TrimSpace(token)
					value = strings.TrimSpace(strings.Trim(value, `"`))
					switch strings.ToLower(token) {
					case "for":
						addr = value
					case "proto":
						proto = value
					case "host":
						host = value
					}

				}
			}
			return
		}

		requestHost := func(r *http.Request) (host string) {
			// not standard, but most popular
			host = r.Header.Get("X-Forwarded-Host")
			if host != "" {
				return
			}

			// RFC 7239
			host = r.Header.Get("Forwarded")
			_, _, host = parseForwarded(host)
			if host != "" {
				return
			}

			// if all else fails fall back to request host
			host = r.Host
			return
		}

		rHost := requestHost(r)
		targetHost, found := clashrayConfig.ClashrayHTTPRedirectMap[rHost]

		if !found || targetHost == "" {
			internalHttpError(w, r, http.StatusInternalServerError, "Redirect URL not found")
			return
		}
		targetURL := targetHost
		hasHttps := strings.HasPrefix(targetHost, "https://") || strings.HasPrefix(targetHost, "ftp://")
		if !hasHttps {
			targetURL = "http://" + strings.TrimPrefix(targetHost, "http://")
		}
		targetURL = strings.TrimSuffix(targetURL, "/")
		http.Redirect(w, r, targetURL+r.URL.RequestURI(), http.StatusTemporaryRedirect)

	})

	internalHTTPClashrayTest = chi.NewRouter()
	internalHTTPClashrayTest.Use(middleware.Logger)
	internalHTTPClashrayTest.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://*", "http://*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "Authorization"},
		MaxAge:         300,
	}))

	internalHTTPClashrayTest.Get("/", func(w http.ResponseWriter, r *http.Request) {
		respondMsg := "PONG"
		viaBridgeRaw := r.Context().Value("ClashrayTestVia")
		viaBridge, ok := viaBridgeRaw.(string)
		if ok && viaBridge != "" {
			respondMsg += " - Via: " + viaBridge
		}
		render.PlainText(w, r, respondMsg)
	})

	internalHTTPClashrayTest.Get("/currAsPublisher", func(w http.ResponseWriter, r *http.Request) {
		respondMsg := clashrayConfig.ClashrayNetCurrAsPublisher
		render.PlainText(w, r, respondMsg)
	})

}

func internalHttpError(w http.ResponseWriter, r *http.Request, status int, errorMessageFormatWithoutError string, v ...any) {
	errorMessageFormat := errorMessageFormatWithoutError
	userMsg := ""
	if len(v) > 0 {
		if _, isError := v[len(v)-1].(error); isError {
			errorMessageFormat = errorMessageFormatWithoutError + ": %v"
			userMsg = fmt.Sprintf(errorMessageFormatWithoutError, v[:len(v)-1]...)
		}
	}
	m := fmt.Sprintf(errorMessageFormat, v...)
	if userMsg == "" {
		userMsg = m
	}
	log.Warnln("internalHTTP: " + m)
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, userMsg)
}

// Copied from GitHub
type singleConnListener struct {
	conn net.Conn
	done bool
	l    sync.Mutex
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.l.Lock()
	if l.done {
		l.l.Unlock()
		return nil, io.ErrClosedPipe
	}
	defer l.l.Unlock()

	l.done = true

	return l.conn, nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.RemoteAddr()
}

func (l *singleConnListener) Close() error {
	return nil
}

func BgHandleInternalHTTPClashraySend() net.Conn {
	conn1, conn2 := net.Pipe()
	go func() {
		err := http.Serve(&singleConnListener{
			conn: conn2,
		}, internalHTTPClashraySend)
		if err != nil {
			log.Warnln("internalHTTP: clashraySend: handling error: %v", err)
		}
	}()
	return conn1
}

func BgHandleInternalHTTPClashrayHTTPRedirect() net.Conn {
	conn1, conn2 := net.Pipe()
	go func() {
		err := http.Serve(&singleConnListener{
			conn: conn2,
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			internalHTTPClashrayHTTPRedirect.ServeHTTP(w, r)
		}))
		if err != nil {
			log.Warnln("internalHTTP: clashrayRedirect: handling error: %v", err)
		}
	}()
	return conn1
}

func BgHandleInternalHTTPClashrayTest(metadata *C.Metadata) net.Conn {
	conn1, conn2 := net.Pipe()
	go func() {
		err := http.Serve(&singleConnListener{
			conn: conn2,
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), "ClashrayTestVia", metadata.InName))
			internalHTTPClashrayTest.ServeHTTP(w, r)
		}))
		if err != nil {
			log.Warnln("internalHTTP: clashrayTest: handling error: %v", err)
		}
	}()
	return conn1
}
