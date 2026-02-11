package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/matindehghanian/node-insecure/config"
	"github.com/matindehghanian/node-insecure/controller"
	"github.com/matindehghanian/node-insecure/controller/rest"
	"github.com/matindehghanian/node-insecure/controller/rpc"
	"github.com/matindehghanian/node-insecure/tools"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.NodeHost, cfg.ServicePort)

	var tlsConfig *tls.Config
	if cfg.TlsEnabled {
		tlsConfig, err = tools.LoadTLSCredentials(cfg.SslCertFile, cfg.SslKeyFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("WARNING: TLS is disabled. Connection is not encrypted!")
	}

	log.Printf("Starting Node: v%s", controller.NodeVersion)

	var shutdownFunc func(ctx context.Context) error
	var service controller.Service

	if cfg.ServiceProtocol == "rest" {
		shutdownFunc, service, err = rest.StartHttpListener(tlsConfig, addr, cfg)
	} else {
		shutdownFunc, service, err = rpc.StartGRPCListener(tlsConfig, addr, cfg)
	}
	if err != nil {
		log.Fatal(err)
	}

	defer service.Disconnect()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt
	<-stopChan
	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err = shutdownFunc(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server gracefully stopped")
}
