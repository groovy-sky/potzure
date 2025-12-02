package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/appendblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
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
	file           *os.File
	azure          *azureBlobClient
	currentBlob    string
	mu             sync.Mutex
}

// NewJSONLogger creates (and rotates) JSON logs under the provided path.
// The supplied path acts as the prefix; files are written as
// <prefix>-YYYYMMDD-HHMM.log.

const (
	azureStorageAccountEnv   = "AZURE_STORAGE_ACCOUNT"
	azureStorageContainerEnv = "AZURE_STORAGE_CONTAINER"
	azureClientIDEnv         = "AZURE_CLIENT_ID"
)

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
	account := os.Getenv(azureStorageAccountEnv)
	container := os.Getenv(azureStorageContainerEnv)
	if account != "" && container != "" {
		prefix := sanitizeAzurePrefix(dir)
		client, err := newAzureBlobClient(account, container, prefix, os.Getenv(azureClientIDEnv))
		if err != nil {
			return nil, err
		}
		logger := &Logger{
			base:      base,
			extension: ext,
			azure:     client,
		}
		if err := logger.rotate(time.Now().UTC()); err != nil {
			return nil, err
		}
		return logger, nil
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
	line, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if l.azure != nil {
		return l.azure.Append(l.currentBlob, line)
	}
	if l.file == nil {
		return errors.New("file handle is nil")
	}
	_, err = l.file.Write(line)
	return err
}

// Close flushes all buffers and closes the file handle.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

func (l *Logger) rotate(now time.Time) error {
	segment := now.Format(segmentFormat)
	if segment == l.currentSegment {
		return nil
	}
	if l.azure != nil {
		l.currentSegment = segment
		l.currentBlob = l.buildBlobPath(segment)
		return l.azure.EnsureAppendBlob(l.currentBlob)
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
	l.currentSegment = segment
	return nil
}

func (l *Logger) buildBlobPath(segment string) string {
	return fmt.Sprintf("%s-%s%s", l.base, segment, l.extension)
}

func sanitizeAzurePrefix(dir string) string {
	if dir == "." || dir == "" {
		return ""
	}
	clean := filepath.ToSlash(dir)
	clean = strings.Trim(clean, "/")
	clean = strings.ReplaceAll(clean, ":", "")
	return clean
}

type azureBlobClient struct {
	account    string
	container  string
	credential azcore.TokenCredential
	prefix     string
}

func newAzureBlobClient(account, container, prefix, clientID string) (*azureBlobClient, error) {
	var cred azcore.TokenCredential
	var err error
	if clientID != "" {
		options := &azidentity.ManagedIdentityCredentialOptions{ID: azidentity.ClientID(clientID)}
		cred, err = azidentity.NewManagedIdentityCredential(options)
	} else {
		cred, err = azidentity.NewManagedIdentityCredential(nil)
	}
	if err != nil {
		return nil, err
	}
	return &azureBlobClient{
		account:    account,
		container:  container,
		credential: cred,
		prefix:     prefix,
	}, nil
}

func (c *azureBlobClient) EnsureAppendBlob(blob string) error {
	client, err := c.newAppendBlobClient(blob)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = client.Create(ctx, nil)
	if err != nil && !bloberror.HasCode(err, bloberror.BlobAlreadyExists) {
		return err
	}
	return nil
}

func (c *azureBlobClient) Append(blob string, data []byte) error {
	client, err := c.newAppendBlobClient(blob)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reader := nopSeekCloser{ReadSeeker: bytes.NewReader(data)}
	_, err = client.AppendBlock(ctx, reader, nil)
	return err
}

func (c *azureBlobClient) newAppendBlobClient(blob string) (*appendblob.Client, error) {
	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", c.account, c.container, c.applyPrefix(blob))
	return appendblob.NewClient(url, c.credential, nil)
}

func (c *azureBlobClient) applyPrefix(blob string) string {
	if c.prefix == "" {
		return blob
	}
	return strings.TrimSuffix(c.prefix, "/") + "/" + strings.TrimPrefix(blob, "/")
}

type nopSeekCloser struct {
	io.ReadSeeker
}

func (n nopSeekCloser) Close() error {
	return nil
}
