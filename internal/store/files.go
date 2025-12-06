package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var filenameCleaner = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ErrEmptyUpload indicates no data was written for a submitted file.
var ErrEmptyUpload = errors.New("empty upload")

// FileStore persists uploaded files and records their hashes.
type FileStore struct {
	baseDir string
}

// SavedFile captures metadata about a stored artifact.
type SavedFile struct {
	DiskPath string
	Hash     string
	Size     int64
}

// NewFileStore creates a filesystem-backed store rooted at dir.
func NewFileStore(dir string) *FileStore {
	return &FileStore{baseDir: dir}
}

// Save writes the stream to disk under a randomized name while computing its hash.
func (fs *FileStore) Save(originalName string, r io.Reader) (SavedFile, error) {
	if err := os.MkdirAll(fs.baseDir, 0o750); err != nil {
		return SavedFile{}, err
	}

	randomPart, err := randomHex(8)
	if err != nil {
		return SavedFile{}, err
	}

	safeName := filenameCleaner.ReplaceAllString(originalName, "")
	if safeName == "" {
		safeName = "upload.bin"
	}

	filename := fmt.Sprintf("%s-%s", randomPart, safeName)
	destPath := filepath.Join(fs.baseDir, filename)

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return SavedFile{}, err
	}
	defer f.Close()

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return SavedFile{}, err
	}
	if written == 0 {
		f.Close()
		_ = os.Remove(destPath)
		return SavedFile{}, ErrEmptyUpload
	}

	return SavedFile{
		DiskPath: destPath,
		Hash:     hex.EncodeToString(h.Sum(nil)),
		Size:     written,
	}, nil
}

func randomHex(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
