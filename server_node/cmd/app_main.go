package cmd

import (
	"context"
	"crypto/tls"
	"github.com/SwanHtetAungPhyo/server_node/cmd/route"
	"github.com/SwanHtetAungPhyo/server_node/internal/config"
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/valyala/fasthttp"
)

// Start initializes and runs the FastHTTP server
func Start(cfg *config.Config) {
	port := strconv.Itoa(cfg.ServerPort)

	routers := route.SetUpRoutes()
	server := &fasthttp.Server{
		Name:                 "MyFastHTTPServer",
		Handler:              routers.Handler,
		ReadTimeout:          5 * time.Second,  // Avoids slow read attacks
		WriteTimeout:         10 * time.Second, // Prevents long write delays
		IdleTimeout:          30 * time.Second, // Controls inactive connections
		MaxConnsPerIP:        100,              // Prevents abuse from a single IP
		MaxRequestsPerConn:   1000,             // Limits excessive requests per connection
		MaxKeepaliveDuration: 60 * time.Second, // Controls keep-alive duration
		KeepHijackedConns:    false,            // Ensures hijacked connections aren't reused
		ReadBufferSize:       4096,             // Optimized buffer size for request parsing
		WriteBufferSize:      4096,             // Optimized buffer size for responses
		ReduceMemoryUsage:    true,             // Optimizes memory allocation
		DisableKeepalive:     false,            // Enables keep-alive for better performance
	}

	certificate, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{
			certificate,
		},
	}

	server.TLSConfig = tlsConfig
	go func() {
		log.Printf("🚀 Server is running on port %s", port)
		if err := server.ListenAndServeTLS(":443", "server.crt", "server.key"); err != nil {
			log.Fatalf("❌ Server failed to start: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	sig := <-sigChan
	log.Printf("⚠️  Received signal: %v. Shutting down server...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("❌ Server shutdown error: %v", err)
	} else {
		log.Println("✅ Server gracefully stopped.")
	}
}
