// Package web serves Sherlock's dashboard and JSON API on localhost.
// Everything the browser needs is compiled into the binary.
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sherlock/internal/monitor"
)

//go:embed static
var static embed.FS

type Server struct {
	m *monitor.Monitor
}

func Handler(m *monitor.Monitor) http.Handler {
	s := &Server{m: m}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/series", s.series)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/events/{id}", s.event)
	mux.HandleFunc("GET /api/events/{id}/files/{name}", s.eventFile)
	mux.HandleFunc("GET /api/notes", s.notes)
	mux.HandleFunc("POST /api/notes", s.addNote)
	mux.HandleFunc("POST /api/capture", s.setCapture)
	mux.HandleFunc("POST /api/throughput/mode", s.setMode)
	mux.HandleFunc("POST /api/throughput/run", s.runTest)
	return guard(mux)
}

// guard rejects cross-site requests. The server only listens on localhost, but
// any web page you visit could otherwise POST to it from your browser.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.Host); err != nil || !isLocal(host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// rangeParams reads from/to (unix ms), defaulting to the last 15 minutes.
func rangeParams(r *http.Request) (int64, int64) {
	now := time.Now().UnixMilli()
	to, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	if err != nil || to <= 0 || to > now+60_000 {
		to = now
	}
	from, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from <= 0 || from >= to {
		from = to - 15*60*1000
	}
	return from, to
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.m.Status())
}

func (s *Server) series(w http.ResponseWriter, r *http.Request) {
	from, to := rangeParams(r)
	points, _ := strconv.Atoi(r.URL.Query().Get("points"))
	if points <= 0 || points > 4000 {
		points = 1200
	}
	ser, err := s.m.Store().Query(from, to, points)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, ser)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	from, to := rangeParams(r)
	ev, err := s.m.Store().Events(from, to, 500)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, ev)
}

// eventDir resolves an event id to its folder, refusing anything that could escape the events directory.
func (s *Server) eventDir(id string) (string, bool) {
	if id == "" || strings.ContainsAny(id, `/\:`) || strings.Contains(id, "..") {
		return "", false
	}
	return filepath.Join(s.m.EventsDir(), id), true
}

func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	dir, ok := s.eventDir(r.PathValue("id"))
	if !ok {
		fail(w, 400, errors.New("bad event id"))
		return
	}
	b, err := os.ReadFile(filepath.Join(dir, "event.json"))
	if errors.Is(err, os.ErrNotExist) {
		if s.m.ActiveEventID() == r.PathValue("id") {
			writeJSON(w, map[string]any{"id": r.PathValue("id"), "complete": false})
			return
		}
		fail(w, 404, errors.New("no snapshot for this event"))
		return
	}
	if err != nil {
		fail(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *Server) eventFile(w http.ResponseWriter, r *http.Request) {
	dir, ok := s.eventDir(r.PathValue("id"))
	name := r.PathValue("name")
	if !ok || name == "" || strings.ContainsAny(name, `/\:`) || strings.Contains(name, "..") {
		fail(w, 400, errors.New("bad file name"))
		return
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err != nil {
		fail(w, 404, errors.New("file not found"))
		return
	}
	if strings.HasSuffix(name, ".pcap") || r.URL.Query().Has("download") {
		w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("id")+"_"+name+`"`)
	} else if strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".csv") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	http.ServeFile(w, r, path)
}

func (s *Server) notes(w http.ResponseWriter, r *http.Request) {
	from, to := rangeParams(r)
	n, err := s.m.Store().Notes(from, to)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, n)
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64*1024)).Decode(v)
}

func (s *Server) addNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	body.Text = strings.TrimSpace(body.Text)
	if body.Text == "" || len(body.Text) > 2000 {
		fail(w, 400, errors.New("a note needs between 1 and 2000 characters"))
		return
	}
	n, err := s.m.AddNote(body.Text)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, n)
}

func (s *Server) setCapture(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	if err := s.m.SetCapture(body.Enabled); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, s.m.Status().Capture)
}

func (s *Server) setMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	if err := s.m.Throughput().SetMode(body.Mode); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, s.m.Throughput().Status())
}

func (s *Server) runTest(w http.ResponseWriter, r *http.Request) {
	if err := s.m.Throughput().RunNow(); err != nil {
		fail(w, 409, err)
		return
	}
	writeJSON(w, s.m.Throughput().Status())
}
