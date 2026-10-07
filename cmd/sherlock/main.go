// Command sherlock watches one network adapter, records connectivity metrics,
// and captures context whenever something goes wrong.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"sherlock/internal/config"
	"sherlock/internal/monitor"
	"sherlock/internal/platform"
	"sherlock/internal/store"
	"sherlock/internal/web"
)

var version = "dev"

const usage = `Sherlock watches a network adapter and records evidence when it misbehaves.

Usage:
  sherlock [run]          start monitoring and serve the dashboard
  sherlock interfaces     list network adapters and their names
  sherlock note "text"    add a note to the timeline ("raised the desk")
  sherlock version

Flags:
  -config path            config file (default: sherlock.json next to the program)
`

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configPath := fs.String("config", defaultConfigPath(), "config file")
	fs.Parse(args)

	var err error
	switch cmd {
	case "run":
		err = run(*configPath)
	case "interfaces":
		err = interfaces()
	case "note":
		err = note(*configPath, strings.Join(fs.Args(), " "))
	case "version":
		fmt.Println("sherlock", version)
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sherlock:", err)
		os.Exit(1)
	}
}

// defaultConfigPath prefers sherlock.json in the working directory (handy for
// `go run`), then next to the executable (handy for double-clicking).
func defaultConfigPath() string {
	if _, err := os.Stat("sherlock.json"); err == nil {
		return "sherlock.json"
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "sherlock.json")
	}
	return "sherlock.json"
}

func run(configPath string) error {
	cfg, created, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	logger, closeLog, err := openLog(filepath.Join(cfg.DataDir, "sherlock.log"))
	if err != nil {
		return err
	}
	defer closeLog()
	if created {
		logger.Printf("wrote default config to %s; edit it and restart to change settings", configPath)
	}
	logger.Printf("sherlock %s starting (config %s, data %s)", version, configPath, cfg.DataDir)

	if cfg.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.MemoryLimitMB) << 20)
	}
	if cfg.LowPriority {
		if err := platform.LowerPriority(); err != nil {
			logger.Printf("could not lower priority: %v", err)
		}
	}

	st, err := store.Open(filepath.Join(cfg.DataDir, "sherlock.db"))
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w (is Sherlock already running?)", cfg.Listen, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := monitor.New(cfg, st, logger)
	srv := &http.Server{
		Handler:           web.Handler(m),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("http: %v", err)
			stop()
		}
	}()
	url := "http://" + ln.Addr().String()
	logger.Printf("dashboard at %s (Ctrl+C to stop)", url)
	if cfg.OpenBrowser {
		if err := platform.OpenBrowser(url); err != nil {
			logger.Printf("could not open a browser: %v", err)
		}
	}

	err = m.Run(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	logger.Printf("stopped")
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// openLog writes to stderr and to a log file, starting the file over once it passes 10 MB.
func openLog(path string) (*log.Logger, func(), error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<20 {
		os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return log.New(io.MultiWriter(os.Stderr, f), "", log.LstdFlags), func() { f.Close() }, nil
}

func interfaces() error {
	list, err := platform.ListInterfaces()
	if err != nil {
		return err
	}
	gw, gwIf, gwErr := platform.DefaultGateway("")
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tSPEED\tKIND\tMAC\tDESCRIPTION")
	for _, s := range list {
		state := "down"
		if s.Up {
			state = "up"
		}
		speed := "-"
		if s.SpeedMbps > 0 {
			speed = fmt.Sprintf("%.0f Mbps", s.SpeedMbps)
		}
		kind := "virtual"
		if s.Physical {
			kind = "physical"
		}
		name := s.Name
		if s.Name == gwIf {
			name += " *"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", name, state, speed, kind, s.MAC, s.Description)
	}
	tw.Flush()
	if gwErr == nil {
		fmt.Printf("\n* default route: gateway %s via %q. Leave \"interface\" empty to watch this one.\n", gw, gwIf)
	}
	return nil
}

func note(configPath, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return errors.New(`usage: sherlock note "what you just did"`)
	}
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post("http://"+cfg.Listen+"/api/notes", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("couldn't reach Sherlock at %s; is it running? (%v)", cfg.Listen, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("note rejected: %s", strings.TrimSpace(string(b)))
	}
	fmt.Println("noted:", text)
	return nil
}
