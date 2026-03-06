package registration

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/datum-cloud/galactic-agent/api/local"
)

const DEFAULT_SOCKET_PATH = "/var/run/galactic/agent.sock"

func connect() (local.LocalClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		fmt.Sprintf("unix://%s", DEFAULT_SOCKET_PATH),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, err
	}
	return local.NewLocalClient(conn), conn, nil
}

func Register(vpc, vpcAttachment string, networks []string) error {
	client, conn, err := connect()
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() //nolint:errcheck

	req := &local.RegisterRequest{
		Vpc:           vpc,
		Vpcattachment: vpcAttachment,
		Networks:      networks,
	}
	_, err = client.Register(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func Deregister(vpc, vpcAttachment string, networks []string) error {
	client, conn, err := connect()
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() //nolint:errcheck

	req := &local.DeregisterRequest{
		Vpc:           vpc,
		Vpcattachment: vpcAttachment,
		Networks:      networks,
	}
	_, err = client.Deregister(ctx, req)
	if err != nil {
		return err
	}
	return nil
}
