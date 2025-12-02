package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"potzure/internal/logging"
	"potzure/internal/server"
	"potzure/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	logPath := flag.String("log", "", "path to events log (defaults to OS cache dir)")
	uploadDir := flag.String("uploads", "uploads", "directory for uploaded files")
	honeypotID := flag.String("id", "hp-1", "honeypot identifier")
	rateLimit := flag.Int("rate", 200, "max requests per 60s per IP")
	flag.Parse()

	if err := os.MkdirAll(*uploadDir, 0o750); err != nil {
		log.Fatalf("failed to create upload dir: %v", err)
	}

	resolvedLogPath, err := resolveLogPath(*logPath)
	if err != nil {
		log.Fatalf("failed to determine log path: %v", err)
	}

	logger, err := logging.NewJSONLogger(resolvedLogPath)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer logger.Close()

	fileStore := store.NewFileStore(*uploadDir)

	srv, err := server.NewServer(server.Config{
		Addr:         *addr,
		Logger:       logger,
		FileStore:    fileStore,
		HoneypotID:   *honeypotID,
		RateLimit:    *rateLimit,
		RateWindow:   time.Minute,
		TemplatesDir: "internal/templates",
	})
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("server stopped: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down honeypot")
	srv.Shutdown()
}

func resolveLogPath(requested string) (string, error) {
	if requested != "" {
		clean := filepath.Clean(requested)
		dir := filepath.Dir(clean)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", err
		}
		return clean, nil
	}

	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		path := filepath.Join(cacheDir, "potzure", "events.log")
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err == nil {
			return path, nil
		}
	}

	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		path := filepath.Join(execDir, "events.log")
		if err := os.MkdirAll(execDir, 0o750); err == nil {
			return path, nil
		}
	}

	path := "events.log"
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	return path, nil
}
