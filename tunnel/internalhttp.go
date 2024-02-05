package tunnel

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/aohorodnyk/mimeheader"
	"github.com/flytam/filenamify"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/metacubex/mihomo/log"
)

var (
	internalHTTPClashraySend     *chi.Mux
	internalHTTPClashrayRedirect *chi.Mux
	internalHTTPClashrayTest     *chi.Mux
	internalHTTPMutex            sync.Mutex
)

func RefreshInternalHTTP(clashrayConfig *Clashray) {
	internalHTTPMutex.Lock()
	defer internalHTTPMutex.Unlock()

	if clashrayConfig.ClashraySendDir != "" {
		os.MkdirAll(clashrayConfig.ClashraySendDir, os.FileMode(0o750))

		internalHTTPClashraySend = chi.NewRouter()
		internalHTTPClashraySend.Use(middleware.Logger)
		internalHTTPClashraySend.Post("/", func(w http.ResponseWriter, r *http.Request) {
			ct := r.Header.Get("Content-Type")
			// RFC 7231, section 3.1.1.5 - empty type
			//   MAY be treated as application/octet-stream
			if ct == "" {
				ct = "application/octet-stream"
			}
			ct, _, err := mime.ParseMediaType(ct)
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Could not media type: %v", err)
				return
			}
			switch {
			case ct == "text/plain":
				textBytes, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024*1024))
				if err != nil {
					internalHttpError(w, r, http.StatusBadRequest, "Could not process text: %v", err)
					return
				}
				os.WriteFile(filepath.Join(clashrayConfig.ClashraySendDir, "text.txt"), textBytes, 0o640)
				render.PlainText(w, r, "OK")
				return
			}

			err = r.ParseMultipartForm(20 * 1024 * 1024)
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Could not parse multipart form: %v", err)
				return
			}
			file, fileHeader, err := r.FormFile("file")
			if err != nil {
				internalHttpError(w, r, http.StatusBadRequest, "Invalid file: %v", err)
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
			if !filepath.IsLocal(safeName) {
				safeName = filepath.Base(safeName) + "_"
			}
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during filename process: %v", err)
				return
			}
			outF, err := os.Create(filepath.Join(clashrayConfig.ClashraySendDir, safeName))
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during file creation: %v", err)
				return
			}
			defer outF.Close()
			_, err = io.Copy(outF, file)
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during file write: %v", err)
				return
			}
			render.PlainText(w, r, "OK")
		})

		internalHTTPClashraySend.Get("/text", func(w http.ResponseWriter, r *http.Request) {
			atRaw := r.Header.Get("Accept")
			at := mimeheader.ParseAcceptHeader(atRaw)
			f, err := os.Open(filepath.Join(clashrayConfig.ClashraySendDir, "text.txt"))
			if err != nil {
				internalHttpError(w, r, http.StatusInternalServerError, "Error during file open: %v", err)
				return
			}
			defer f.Close()
			if at.Match("text/plain") {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, err = io.Copy(w, io.LimitReader(f, 1*1024*1024*1024))
				if err != nil {
					internalHttpError(w, r, http.StatusInternalServerError, "Error during stream copy: %v", err)
					return
				}
				return
			}
			if at.Match("application/json") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				fileBytes, err := io.ReadAll(io.LimitReader(f, 1*1024*1024*1024))
				if err != nil {
					internalHttpError(w, r, http.StatusInternalServerError, "Error during file read: %v", err)
					return
				}
				render.JSON(w, r, map[string]interface{}{
					"data": fileBytes,
				})
				return
			}
			internalHttpError(w, r, http.StatusBadRequest, "No proper Accept type received")
		})
	} else {
		internalHTTPClashraySend = chi.NewRouter()
		internalHTTPClashraySend.Use(middleware.Logger)
		internalHTTPClashraySend.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			internalHttpError(w, r, http.StatusForbidden, "Clashray Send Not Available")
		}))
	}

	internalHTTPClashrayRedirect = chi.NewRouter()
	internalHTTPClashrayRedirect.Use(middleware.Logger)
	internalHTTPClashrayRedirect.Get("/", func(w http.ResponseWriter, r *http.Request) {
		targetHostRaw := r.Context().Value("ClashrayRedirectHost")
		targetHost, hostConvertOK := targetHostRaw.(string)
		if !hostConvertOK || targetHost == "" {
			internalHttpError(w, r, http.StatusInternalServerError, "Bad redirect url")
			return
		}
		http.Redirect(w, r, targetHost+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})

	internalHTTPClashrayTest = chi.NewRouter()
	internalHTTPClashrayTest.Use(middleware.Logger)
	internalHTTPClashrayTest.Get("/", func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "PONG")
	})

}

func internalHttpError(w http.ResponseWriter, r *http.Request, status int, errorMessageFormat string, v ...any) {
	m := fmt.Sprintf(errorMessageFormat, v...)
	log.Warnln("internalHTTP: " + m)
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, m)
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

func BgHandleInternalHTTPClashrayRedirect(targetHost string) net.Conn {
	conn1, conn2 := net.Pipe()
	go func() {
		err := http.Serve(&singleConnListener{
			conn: conn2,
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), "ClashrayRedirectHost", targetHost))
			internalHTTPClashrayRedirect.ServeHTTP(w, r)
		}))
		if err != nil {
			log.Warnln("internalHTTP: clashrayRedirect: handling targetHost=%s error: %v", targetHost, err)
		}
	}()
	return conn1
}

func BgHandleInternalHTTPClashrayTest() net.Conn {
	conn1, conn2 := net.Pipe()
	go func() {
		err := http.Serve(&singleConnListener{
			conn: conn2,
		}, internalHTTPClashrayTest)
		if err != nil {
			log.Warnln("internalHTTP: clashrayTest: handling error: %v", err)
		}
	}()
	return conn1
}
