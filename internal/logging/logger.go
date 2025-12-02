package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	file           *os.File
	azure          *azureBlobClient
	azurePrefix    string
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
	azureResource            = "https://storage.azure.com/"
	metadataEndpoint         = "http://169.254.169.254/metadata/identity/oauth2/token"
	metadataAPIVersion       = "2018-02-01"
	azureAPIVersion          = "2021-04-10"
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
		client := newAzureBlobClient(account, container, prefix, os.Getenv(azureClientIDEnv))
		logger := &Logger{
			base:        base,
			extension:   ext,
			azure:       client,
			azurePrefix: prefix,
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
	name := fmt.Sprintf("%s-%s%s", l.base, segment, l.extension)
	if l.azurePrefix == "" {
		return name
	}
	return strings.TrimSuffix(l.azurePrefix, "/") + "/" + name
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
	account       string
	container     string
	prefix        string
	client        *http.Client
	tokenProvider *managedIdentityTokenProvider
}

func newAzureBlobClient(account, container, prefix, clientID string) *azureBlobClient {
	return &azureBlobClient{
		account:   account,
		container: container,
		prefix:    prefix,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		tokenProvider: newManagedIdentityTokenProvider(azureResource, clientID),
	}
}

func (c *azureBlobClient) EnsureAppendBlob(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	urlStr := c.buildURL(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("x-ms-version", azureAPIVersion)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-blob-type", "AppendBlob")
	req.Header.Set("Content-Length", "0")
	if err := c.authorize(req); err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusAccepted {
		return nil
	}
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	return fmt.Errorf("azure blob create failed: %s", resp.Status)
}

func (c *azureBlobClient) Append(path string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := url.Parse(c.buildURL(path))
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("comp", "appendblock")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("x-ms-version", azureAPIVersion)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))
	req.Header.Set("Content-Type", "application/json")
	if err := c.authorize(req); err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("azure append failed: %s", resp.Status)
	}
	return nil
}

func (c *azureBlobClient) buildURL(path string) string {
	pl := strings.TrimPrefix(path, "/")
	basePath := pl
	if c.prefix != "" {
		basePath = strings.TrimSuffix(c.prefix, "/") + "/" + basePath
	}
	u := url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s.blob.core.windows.net", c.account),
		Path:   fmt.Sprintf("/%s/%s", c.container, basePath),
	}
	return u.String()
}

func (c *azureBlobClient) authorize(req *http.Request) error {
	token, err := c.tokenProvider.Token(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

type managedIdentityTokenProvider struct {
	resource  string
	clientID  string
	client    *http.Client
	mu        sync.Mutex
	token     string
	expiresOn time.Time
}

func newManagedIdentityTokenProvider(resource, clientID string) *managedIdentityTokenProvider {
	return &managedIdentityTokenProvider{
		resource: resource,
		clientID: clientID,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *managedIdentityTokenProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Until(p.expiresOn) > time.Minute && p.token != "" {
		return p.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataEndpoint, http.NoBody)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Set("api-version", metadataAPIVersion)
	q.Set("resource", p.resource)
	if p.clientID != "" {
		q.Set("client_id", p.clientID)
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Metadata", "true")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("managed identity token request failed: %s", resp.Status)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("managed identity response missing access_token")
	}
	expires, err := parseExpiresOn(payload.ExpiresOn)
	if err != nil {
		return "", err
	}
	p.token = payload.AccessToken
	p.expiresOn = expires
	return p.token, nil
}

func parseExpiresOn(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, errors.New("expires_on empty")
	}
	if epoch, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(epoch, 0), nil
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse expires_on: %s", raw)
}
