package local

import (
	"context"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Local struct {
	UnimplementedLocalServer
	SocketPath        string
	RegisterHandler   func(string, string, []string) error
	DeregisterHandler func(string, string, []string) error
}

func (l *Local) Register(ctx context.Context, req *RegisterRequest) (*RegisterReply, error) {
	if err := l.RegisterHandler(req.GetVpc(), req.GetVpcattachment(), req.GetNetworks()); err != nil {
		return nil, err
	}
	return &RegisterReply{Confirmed: true}, nil
}

func (l *Local) Deregister(ctx context.Context, req *DeregisterRequest) (*DeregisterReply, error) {
	if err := l.DeregisterHandler(req.GetVpc(), req.GetVpcattachment(), req.GetNetworks()); err != nil {
		return nil, err
	}
	return &DeregisterReply{Confirmed: true}, nil
}

func (l *Local) Serve(ctx context.Context) error {
	// unix socket should be unlinked if it exists first
	// see: https://github.com/golang/go/issues/70985
	err := os.Remove(l.SocketPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", l.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close() //nolint:errcheck

	s := grpc.NewServer()
	RegisterLocalServer(s, l)

	reflection.Register(s)

	routineErr := make(chan error, 1)
	go func() {
		log.Printf("gRPC listening: unix://%s", l.SocketPath)
		if err := s.Serve(listener); err != nil {
			routineErr <- err
			return
		}
		routineErr <- nil
	}()

	<-ctx.Done()
	s.Stop()
	log.Println("gRPC stopped")
	return <-routineErr
}
