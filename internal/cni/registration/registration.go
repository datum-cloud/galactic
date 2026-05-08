// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.datum.net/galactic/pkg/proto/local"
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

// Register tells the local agent that this node now hosts a pod for
// the given (vpcHex, attachHex). The agent reads pod IPs from the
// VPCAttachment informer cache; the CNI plugin no longer pushes them.
func Register(vpc, vpcAttachment string) error {
	client, conn, err := connect()
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &local.RegisterRequest{
		Vpc:           vpc,
		Vpcattachment: vpcAttachment,
	}
	_, err = client.Register(ctx, req)
	return err
}

func Deregister(vpc, vpcAttachment string) error {
	client, conn, err := connect()
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &local.DeregisterRequest{
		Vpc:           vpc,
		Vpcattachment: vpcAttachment,
	}
	_, err = client.Deregister(ctx, req)
	return err
}
