// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/identity"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

func newQueryCommand() *cobra.Command {
	var (
		gatewayAddr, nodeAddr, nodeName, nodePod, namespace string
		cell, operator, family                              string
		nodes                                               []string
		info                                                bool
		timeout                                             time.Duration
		t                                                   tlsFlags
	)
	cmd := &cobra.Command{
		Use:   "query [TYPE [TARGET]]",
		Short: "Run a debug query with an operator identity, through the gateway or against one node",
		Long: `Runs one query and prints the result as JSON. TYPE is one of
RouteLookup, ASPath, Community, LargeCommunity, BGPSummary, Ping or
Traceroute; probe targets must be numeric addresses.

With --gateway it calls the cell gateway's debug service, which applies the
public destination policy. With --node it calls one node sidecar directly,
whose operator destination policy may carry narrow lab exceptions. --info
asks a node for its identity and availability instead.`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (gatewayAddr == "") == (nodeAddr == "") {
				return errors.New("set exactly one of --gateway or --node")
			}
			creds := t.credentials(identity.Operator(cell, operator))
			if err := creds.Reload(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout+5*time.Second)
			defer cancel()

			var q query.Query
			if !info {
				if len(args) == 0 {
					return errors.New("TYPE is required")
				}
				q.Type = query.Type(args[0])
				if len(args) > 1 {
					q.Target = args[1]
				}
				q.AddressFamily = query.AddressFamily(family)
				var err error
				if q, err = query.Canonicalize(q); err != nil {
					return err
				}
			}

			var out proto.Message
			if gatewayAddr != "" {
				conn, err := grpc.NewClient(gatewayAddr, grpc.WithTransportCredentials(credentials.NewTLS(
					creds.ClientConfig(identity.Gateway(cell)))))
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()
				resp, err := fabricv1.NewFabricGatewayServiceClient(conn).Query(ctx, &fabricv1.QueryRequest{
					Query: node.QueryToProto(q), Nodes: nodes, Timeout: durationpb.New(timeout),
				})
				if err != nil {
					return fmt.Errorf("%s: %s", errcode.Of(err), errcode.Message(err))
				}
				out = resp
			} else {
				if nodePod == "" || nodeName == "" {
					return errors.New("--node needs --node-name and --node-pod (the node's fabric-api-certs pod)")
				}
				conn, err := grpc.NewClient(nodeAddr, grpc.WithTransportCredentials(credentials.NewTLS(
					creds.ClientConfig(identity.Node(cell, namespace, nodePod)))))
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()
				c := fabricv1.NewFabricServiceClient(conn)
				if info {
					resp, err := c.Info(ctx, &fabricv1.InfoRequest{})
					if err != nil {
						return fmt.Errorf("%s: %s", errcode.Of(err), errcode.Message(err))
					}
					out = resp
				} else {
					id := make([]byte, 8)
					_, _ = rand.Read(id)
					resp, err := c.Execute(ctx, &fabricv1.ExecuteRequest{
						RequestId: "operator-" + hex.EncodeToString(id), Node: nodeName, Query: node.QueryToProto(q),
						ExpiresAt: timestamppb.New(time.Now().Add(timeout)),
					})
					if err != nil {
						return fmt.Errorf("%s: %s", errcode.Of(err), errcode.Message(err))
					}
					out = resp
				}
			}
			b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(out)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(os.Stdout, string(b))
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&gatewayAddr, "gateway", "", "Gateway debug service address (host:port)")
	f.StringVar(&nodeAddr, "node", "", "Node sidecar address (host:port)")
	f.StringVar(&nodeName, "node-name", "", "Node name, with --node")
	f.StringVar(&nodePod, "node-pod", "",
		"The pod whose identity the node's sidecar presents: the fabric-api-certs pod on that node, with --node")
	f.StringVar(&namespace, "namespace", "galactic-system", "The fabric-router pods' namespace")
	f.StringVar(&cell, "cell", envOr("CELL", ""), "Cell name (env CELL)")
	f.StringVar(&operator, "operator", envOr("FABRIC_API_OPERATOR", ""),
		"Operator name in this certificate (env FABRIC_API_OPERATOR)")
	f.StringVar(&family, "family", "", "Address family: IPv4 or IPv6 (default: inferred, else IPv4)")
	f.StringSliceVar(&nodes, "nodes", nil, "Restrict a gateway query to these nodes")
	f.BoolVar(&info, "info", false, "Ask the node for its identity and availability")
	f.DurationVar(&timeout, "timeout", query.MaxNodeExecution, "Query timeout")
	t.register(cmd, ".")
	return cmd
}
