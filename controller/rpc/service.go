package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Service struct {
	common.UnimplementedNodeServiceServer
	controller.Controller
}

func New(cfg *config.Config) *Service {
	return &Service{
		Controller: *controller.New(cfg),
	}
}

func StartGRPCListener(tlsConfig *tls.Config, addr string, cfg *config.Config) (func(ctx context.Context) error, controller.Service, error) {
	s := New(cfg)

	// Create the gRPC server with conditional middleware
	// Set max message size to 64MB to handle large configs and user data
	const maxMsgSize = 64 * 1024 * 1024 // 64MB

	var serverOpts []grpc.ServerOption
	if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}
	serverOpts = append(serverOpts,
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.UnaryInterceptor(ConditionalMiddleware(s)),
		grpc.StreamInterceptor(ConditionalStreamMiddleware(s)),
	)

	grpcServer := grpc.NewServer(serverOpts...)

	// Register the service
	common.RegisterNodeServiceServer(grpcServer, s)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		if tlsConfig != nil {
			log.Println("gRPC Server (TLS) listening on", addr)
		} else {
			log.Println("gRPC Server (no TLS) listening on", addr)
		}
		log.Println("Press Ctrl+C to stop")
		if err = grpcServer.Serve(listener); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Create a shutdown function for gRPC server
	return func(ctx context.Context) error {
		// Graceful stop for gRPC server
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()

		// Wait for server to stop or context to timeout
		select {
		case <-stopped:
			return nil
		case <-ctx.Done():
			grpcServer.Stop() // Force stop if graceful stop times out
			return ctx.Err()
		}
	}, s, nil
}
