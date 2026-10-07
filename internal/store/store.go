// Package store keeps Sherlock's history in a single SQLite file.
//
// Samples are buffered in memory and written in one transaction every few
// seconds, so disk activity stays low and the in-memory buffer stays small.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// Probe targets.
const (
	TargetGateway  = 1
	TargetInternet = 2
	TargetDNS      = 3
)

// LinkRow is one interface reading. Counters are deltas since the previous reading.
type LinkRow struct {
	TS         int64 // unix milliseconds
	Up         bool
	SpeedMbps  float64
	RxBps      float64
	TxBps      float64
	RxErrors   uint64
	TxErrors   uint64
	RxDiscards uint64
	TxDiscards uint64
}

// ProbeRow is one ping or DNS lookup. RTTms is NaN when it failed.
type ProbeRow struct {
	TS     int64
	Target int
	RTTms  float64
}

type ThroughputRow struct {
	TS          int64   `json:"ts"`
	DownMbps    float64 `json:"down_mbps"`
	UpMbps      float64 `json:"up_mbps"`
	Retransmits int64   `json:"retransmits"`
	Server      string  `json:"server"`
	Error       string  `json:"error,omitempty"`
}

type Event struct {
	ID          string   `json:"id"`
	StartTS     int64    `json:"start"`
	EndTS       int64    `json:"end"`
	WindowStart int64    `json:"window_start"`
	Kinds       []string `json:"kinds"`
	Summary     string   `json:"summary"`
	// Full is false for triggers logged during the cooldown, which have no snapshot folder.
	Full bool `json:"full"`
}

type Note struct {
	ID   int64  `json:"id"`
	TS   int64  `json:"ts"`
	Text string `json:"text"`
}

type Store struct {
	db *sql.DB

	mu     sync.Mutex
	links  []LinkRow
	probes []ProbeRow
}

const schema = `
CREATE TABLE IF NOT EXISTS link_samples (
	ts INTEGER PRIMARY KEY,
	up INTEGER NOT NULL,
	speed_mbps REAL NOT NULL,
	rx_bps REAL NOT NULL,
	tx_bps REAL NOT NULL,
	rx_errors INTEGER NOT NULL,
	tx_errors INTEGER NOT NULL,
	rx_discards INTEGER NOT NULL,
	tx_discards INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS probe_samples (
	target INTEGER NOT NULL,
	ts INTEGER NOT NULL,
	rtt_ms REAL,
	PRIMARY KEY (target, ts)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS throughput_runs (
	ts INTEGER PRIMARY KEY,
	down_mbps REAL,
	up_mbps REAL,
	retransmits INTEGER,
	server TEXT,
	error TEXT
);
CREATE TABLE IF NOT EXISTS events (
	id TEXT PRIMARY KEY,
	start_ts INTEGER NOT NULL,
	end_ts INTEGER NOT NULL,
	window_start INTEGER NOT NULL,
	kinds TEXT NOT NULL,
	summary TEXT NOT NULL,
	is_full INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_start ON events(start_ts);
CREATE TABLE IF NOT EXISTS notes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notes_ts ON notes(ts);
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, err
	}
	// One connection: writes are batched and queries are small, so there is
	// nothing to gain from a pool, and pragmas apply to every statement.
	db.SetMaxOpenConns(1)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-4000", // ~4 MB page cache
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	s.Flush()
	return s.db.Close()
}

func (s *Store) AddLink(r LinkRow) {
	s.mu.Lock()
	s.links = append(s.links, r)
	s.mu.Unlock()
}

func (s *Store) AddProbe(r ProbeRow) {
	s.mu.Lock()
	s.probes = append(s.probes, r)
	s.mu.Unlock()
}

// Flush writes buffered samples in one transaction.
func (s *Store) Flush() error {
	s.mu.Lock()
	links, probes := s.links, s.probes
	s.links, s.probes = make([]LinkRow, 0, cap(links)), make([]ProbeRow, 0, cap(probes))
	s.mu.Unlock()
	if len(links) == 0 && len(probes) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(links) > 0 {
		st, err := tx.Prepare(`INSERT OR REPLACE INTO link_samples VALUES (?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		for _, r := range links {
			if _, err := st.Exec(r.TS, boolInt(r.Up), r.SpeedMbps, r.RxBps, r.TxBps,
				int64(r.RxErrors), int64(r.TxErrors), int64(r.RxDiscards), int64(r.TxDiscards)); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
	}
	if len(probes) > 0 {
		st, err := tx.Prepare(`INSERT OR REPLACE INTO probe_samples VALUES (?,?,?)`)
		if err != nil {
			return err
		}
		for _, r := range probes {
			if _, err := st.Exec(r.Target, r.TS, nullFloat(r.RTTms)); err != nil {
				st.Close()
				return err
			}
		}
		st.Close()
	}
	return tx.Commit()
}

func (s *Store) AddThroughput(r ThroughputRow) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO throughput_runs VALUES (?,?,?,?,?,?)`,
		r.TS, nullFloat(r.DownMbps), nullFloat(r.UpMbps), r.Retransmits, r.Server, r.Error)
	return err
}

func (s *Store) Throughput(from, to int64) ([]ThroughputRow, error) {
	rows, err := s.db.Query(`SELECT ts, down_mbps, up_mbps, retransmits, server, error
		FROM throughput_runs WHERE ts BETWEEN ? AND ? ORDER BY ts`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThroughputRow{}
	for rows.Next() {
		var r ThroughputRow
		var down, up sql.NullFloat64
		if err := rows.Scan(&r.TS, &down, &up, &r.Retransmits, &r.Server, &r.Error); err != nil {
			return nil, err
		}
		r.DownMbps, r.UpMbps = nanIfNull(down), nanIfNull(up)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) PutEvent(e Event) error {
	kinds, _ := json.Marshal(e.Kinds)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?)`,
		e.ID, e.StartTS, e.EndTS, e.WindowStart, string(kinds), e.Summary, boolInt(e.Full))
	return err
}

func (s *Store) Events(from, to int64, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT id, start_ts, end_ts, window_start, kinds, summary, is_full
		FROM events WHERE end_ts >= ? AND start_ts <= ? ORDER BY start_ts DESC LIMIT ?`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var kinds string
		var full int
		if err := rows.Scan(&e.ID, &e.StartTS, &e.EndTS, &e.WindowStart, &kinds, &e.Summary, &full); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(kinds), &e.Kinds)
		e.Full = full == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AddNote(ts int64, text string) (Note, error) {
	res, err := s.db.Exec(`INSERT INTO notes (ts, text) VALUES (?, ?)`, ts, text)
	if err != nil {
		return Note{}, err
	}
	id, _ := res.LastInsertId()
	return Note{ID: id, TS: ts, Text: text}, nil
}

func (s *Store) Notes(from, to int64) ([]Note, error) {
	rows, err := s.db.Query(`SELECT id, ts, text FROM notes WHERE ts BETWEEN ? AND ? ORDER BY ts`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Note{}
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.TS, &n.Text); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) Setting(key string) (string, bool) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v, err == nil
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO settings VALUES (?, ?)`, key, value)
	return err
}

// Prune deletes samples older than the cutoff. Events and notes are kept.
func (s *Store) Prune(before int64) error {
	for _, q := range []string{
		`DELETE FROM link_samples WHERE ts < ?`,
		`DELETE FROM probe_samples WHERE ts < ?`,
		`DELETE FROM throughput_runs WHERE ts < ?`,
	} {
		if _, err := s.db.Exec(q, before); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// Series is the dashboard's chart data: one value per time bucket, aligned on T.
// Values are nil where a bucket has no data.
type Series struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
	Step int64 `json:"step"`
	// T holds bucket start times in unix seconds, which is what uPlot expects.
	T   []float64             `json:"t"`
	Ser map[string][]*float64 `json:"series"`
}

// Query aggregates samples between from and to (unix ms) into about `points` buckets.
func (s *Store) Query(from, to int64, points int) (*Series, error) {
	if err := s.Flush(); err != nil {
		return nil, err
	}
	if points < 10 {
		points = 10
	}
	step := (to - from) / int64(points)
	if step < 1000 {
		step = 1000
	}
	step = (step + 999) / 1000 * 1000
	from = from / step * step
	n := int((to-from)/step) + 1

	out := &Series{From: from, To: to, Step: step, T: make([]float64, n), Ser: map[string][]*float64{}}
	for i := range out.T {
		out.T[i] = float64(from+int64(i)*step) / 1000
	}
	col := func(name string) []*float64 {
		c, ok := out.Ser[name]
		if !ok {
			c = make([]*float64, n)
			out.Ser[name] = c
		}
		return c
	}
	idx := func(b int64) int {
		i := int((b - from) / step)
		if i < 0 || i >= n {
			return -1
		}
		return i
	}

	rows, err := s.db.Query(`SELECT ts / ? * ? AS b,
			MIN(up), MIN(speed_mbps), MAX(speed_mbps),
			AVG(rx_bps), MAX(rx_bps), AVG(tx_bps), MAX(tx_bps),
			SUM(rx_errors), SUM(tx_errors), SUM(rx_discards), SUM(tx_discards)
		FROM link_samples WHERE ts BETWEEN ? AND ? GROUP BY b`, step, step, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b int64
		var v [11]float64
		if err := rows.Scan(&b, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10]); err != nil {
			rows.Close()
			return nil, err
		}
		i := idx(b)
		if i < 0 {
			continue
		}
		names := []string{"link_up", "speed_min", "speed_max", "rx_mbps", "rx_mbps_max", "tx_mbps", "tx_mbps_max",
			"rx_errors", "tx_errors", "rx_discards", "tx_discards"}
		for k, name := range names {
			x := v[k]
			if k >= 3 && k <= 6 {
				x /= 1e6
			}
			col(name)[i] = &x
		}
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT target, ts / ? * ? AS b,
			AVG(rtt_ms), MAX(rtt_ms), COUNT(*), SUM(rtt_ms IS NULL)
		FROM probe_samples WHERE ts BETWEEN ? AND ? GROUP BY target, b`, step, step, from, to)
	if err != nil {
		return nil, err
	}
	prefix := map[int]string{TargetGateway: "gw", TargetInternet: "inet", TargetDNS: "dns"}
	for rows.Next() {
		var target int
		var b int64
		var avg, max sql.NullFloat64
		var count, lost float64
		if err := rows.Scan(&target, &b, &avg, &max, &count, &lost); err != nil {
			rows.Close()
			return nil, err
		}
		i := idx(b)
		p, ok := prefix[target]
		if i < 0 || !ok {
			continue
		}
		if avg.Valid {
			a, m := avg.Float64, max.Float64
			col(p + "_avg")[i] = &a
			col(p + "_max")[i] = &m
		}
		loss := lost / count * 100
		col(p + "_loss")[i] = &loss
	}
	rows.Close()

	runs, err := s.Throughput(from, to)
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		i := idx(r.TS / step * step)
		if i < 0 {
			continue
		}
		if !math.IsNaN(r.DownMbps) {
			d := r.DownMbps
			col("iperf_down")[i] = &d
		}
		if !math.IsNaN(r.UpMbps) {
			u := r.UpMbps
			col("iperf_up")[i] = &u
		}
	}
	return out, nil
}

// RawLinks and RawProbes return unaggregated samples, used for event snapshots.
func (s *Store) RawLinks(from, to int64) ([]LinkRow, error) {
	rows, err := s.db.Query(`SELECT ts, up, speed_mbps, rx_bps, tx_bps, rx_errors, tx_errors, rx_discards, tx_discards
		FROM link_samples WHERE ts BETWEEN ? AND ? ORDER BY ts`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LinkRow
	for rows.Next() {
		var r LinkRow
		var up int
		var rxe, txe, rxd, txd int64
		if err := rows.Scan(&r.TS, &up, &r.SpeedMbps, &r.RxBps, &r.TxBps, &rxe, &txe, &rxd, &txd); err != nil {
			return nil, err
		}
		r.Up = up == 1
		r.RxErrors, r.TxErrors, r.RxDiscards, r.TxDiscards = uint64(rxe), uint64(txe), uint64(rxd), uint64(txd)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RawProbes(from, to int64) ([]ProbeRow, error) {
	rows, err := s.db.Query(`SELECT target, ts, rtt_ms FROM probe_samples WHERE ts BETWEEN ? AND ? ORDER BY ts, target`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeRow
	for rows.Next() {
		var r ProbeRow
		var rtt sql.NullFloat64
		if err := rows.Scan(&r.Target, &r.TS, &rtt); err != nil {
			return nil, err
		}
		r.RTTms = nanIfNull(rtt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Now is the store's clock in unix milliseconds.
func Now() int64 { return time.Now().UnixMilli() }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullFloat(f float64) any {
	if math.IsNaN(f) {
		return nil
	}
	return f
}

func nanIfNull(f sql.NullFloat64) float64 {
	if !f.Valid {
		return math.NaN()
	}
	return f.Float64
}
