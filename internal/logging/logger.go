package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event describes a single honeypot interaction that is persisted to disk.
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	SrcIP       string                 `json:"src_ip"`
	Method      string                 `json:"method"`
	URI         string                 `json:"uri"`
	Headers     map[string]string      `json:"headers"`
	UserAgent   string                 `json:"user_agent"`
	BodyHash    string                 `json:"body_hash"`
	Form        map[string][]string    `json:"form,omitempty"`
	UploadPaths []string               `json:"upload_paths,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	HoneypotID  string                 `json:"honeypot_id"`
}

const segmentFormat = "20060102-1504"

// Logger writes JSON events to timestamped log segments.
type Logger struct {
	dir            string
	base           string
	extension      string
	currentSegment string
	enc            *json.Encoder
	file           *os.File
	mu             sync.Mutex
}

// NewJSONLogger creates (and rotates) JSON logs under the provided path.
// The supplied path acts as the prefix; files are written as
// <prefix>-YYYYMMDD-HHMM.log.
func NewJSONLogger(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if dir == "." && !strings.Contains(path, string(filepath.Separator)) {
		dir = "."
	}
	base := filepath.Base(path)
	if base == "." || base == "" {
		base = "events.log"
	}
	ext := filepath.Ext(base)
	if ext == "" {
		ext = ".log"
	}
	base = strings.TrimSuffix(base, ext)
	if base == "" {
		base = "events"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l := &Logger{dir: dir, base: base, extension: ext}
	if err := l.rotate(time.Now().UTC()); err != nil {
		return nil, err
	}
	return l, nil
}

// Log persists one event in a thread-safe fashion.
func (l *Logger) Log(evt Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.rotate(evt.Timestamp.UTC()); err != nil {
		return err
	}
	return l.enc.Encode(evt)
}

// Close flushes all buffers and closes the file handle.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	l.enc = nil
	return err
}

func (l *Logger) rotate(now time.Time) error {
	segment := now.Format(segmentFormat)
	if segment == l.currentSegment && l.file != nil {
		return nil
	}
	if l.file != nil {
		_ = l.file.Close()
	}
	filename := fmt.Sprintf("%s-%s%s", l.base, segment, l.extension)
	path := filepath.Join(l.dir, filename)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	l.file = f
	l.enc = json.NewEncoder(f)
	l.currentSegment = segment
	return nil
}
