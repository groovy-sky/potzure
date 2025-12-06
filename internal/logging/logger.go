package logging

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
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
	base           string
	extension      string
	currentSegment string
	azure          *azureBlobClient
	currentBlob    string
	headerWritten  bool
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
	base := filepath.Base(path)
	if base == "." || base == "" {
		base = "events.log"
	}
	ext := filepath.Ext(base)
	base = strings.TrimSuffix(base, ext)
	if base == "" {
		base = "events"
	}
	ext = ".csv"
	account := os.Getenv(azureStorageAccountEnv)
	container := os.Getenv(azureStorageContainerEnv)
	if account == "" || container == "" {
		return nil, fmt.Errorf("azure blob logging requires %s and %s", azureStorageAccountEnv, azureStorageContainerEnv)
	}
	client, err := newAzureBlobClient(account, container, os.Getenv(azureClientIDEnv))
	if err != nil {
		return nil, err
	}
	l := &Logger{base: base, extension: ext, azure: client}
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
	if !l.headerWritten {
		header, err := marshalCSVRecord([]string{"src_ip", "uri", "method", "user_agent", "form"})
		if err != nil {
			return err
		}
		if err := l.azure.Append(l.currentBlob, header); err != nil {
			return err
		}
		l.headerWritten = true
	}
	record, err := marshalCSVRecord([]string{
		evt.SrcIP,
		evt.URI,
		evt.Method,
		evt.UserAgent,
		encodeForm(evt.Form),
	})
	if err != nil {
		return err
	}
	return l.azure.Append(l.currentBlob, record)
}

// Close flushes all buffers and closes the file handle.
func (l *Logger) Close() error {
	return nil
}

func (l *Logger) rotate(now time.Time) error {
	segment := now.Format(segmentFormat)
	if segment == l.currentSegment {
		return nil
	}
	l.currentSegment = segment
	l.currentBlob = l.buildBlobPath(segment)
	created, err := l.azure.EnsureAppendBlob(l.currentBlob)
	if err != nil {
		return err
	}
	l.headerWritten = !created
	return nil
}

func (l *Logger) buildBlobPath(segment string) string {
	return fmt.Sprintf("%s-%s%s", l.base, segment, l.extension)
}

type azureBlobClient struct {
	account    string
	container  string
	credential azcore.TokenCredential
}

func newAzureBlobClient(account, container, clientID string) (*azureBlobClient, error) {
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
	}, nil
}

func (c *azureBlobClient) EnsureAppendBlob(blob string) (bool, error) {
	client, err := c.newAppendBlobClient(blob)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = client.Create(ctx, nil)
	if err == nil {
		return true, nil
	}
	if bloberror.HasCode(err, bloberror.BlobAlreadyExists) {
		return false, nil
	}
	return false, err
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
	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", c.account, c.container, strings.TrimPrefix(blob, "/"))
	return appendblob.NewClient(url, c.credential, nil)
}

type nopSeekCloser struct {
	io.ReadSeeker
}

func (n nopSeekCloser) Close() error {
	return nil
}

func marshalCSVRecord(record []string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Comma = '\\'
	if err := w.Write(record); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeForm(form map[string][]string) string {
	if len(form) == 0 {
		return ""
	}
	b, err := json.Marshal(form)
	if err != nil {
		return ""
	}
	return string(b)
}
