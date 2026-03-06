/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package agent

import (
	"context"
	"log"

	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"go.datum.net/galactic/internal/agent/srv6"
	"go.datum.net/galactic/pkg/common/util"
	"go.datum.net/galactic/pkg/proto/local"
	"go.datum.net/galactic/pkg/proto/remote"
)

type agentFlags struct {
	configFile string
}

func NewCommand() *cobra.Command {
	flags := &agentFlags{}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the Galactic network agent",
		Long: `The agent runs on each node and manages local SRv6 routes and VRF configurations.
It communicates with the CNI plugin via a local gRPC socket and with the router via MQTT.`,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConfig(flags.configFile)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
	}

	cmd.Flags().StringVar(&flags.configFile, "config", "", "Config file path")
	cmd.Flags().String("srv6-net", "fc00::/56", "SRv6 network CIDR")
	cmd.Flags().String("socket-path", "/var/run/galactic/agent.sock", "Unix socket path for CNI communication")
	cmd.Flags().String("mqtt-url", "tcp://mqtt:1883", "MQTT broker URL")
	cmd.Flags().String("mqtt-clientid", "", "MQTT client ID (empty for random)")
	cmd.Flags().String("mqtt-username", "", "MQTT username")
	cmd.Flags().String("mqtt-password", "", "MQTT password")
	cmd.Flags().Int("mqtt-qos", 1, "MQTT QoS level (0, 1, or 2)")
	cmd.Flags().String("mqtt-topic-receive", "galactic/default/receive", "MQTT topic for receiving messages")
	cmd.Flags().String("mqtt-topic-send", "galactic/default/send", "MQTT topic for sending messages")

	// Bind flags to viper
	viper.BindPFlag("srv6_net", cmd.Flags().Lookup("srv6-net"))
	viper.BindPFlag("socket_path", cmd.Flags().Lookup("socket-path"))
	viper.BindPFlag("mqtt_url", cmd.Flags().Lookup("mqtt-url"))
	viper.BindPFlag("mqtt_clientid", cmd.Flags().Lookup("mqtt-clientid"))
	viper.BindPFlag("mqtt_username", cmd.Flags().Lookup("mqtt-username"))
	viper.BindPFlag("mqtt_password", cmd.Flags().Lookup("mqtt-password"))
	viper.BindPFlag("mqtt_qos", cmd.Flags().Lookup("mqtt-qos"))
	viper.BindPFlag("mqtt_topic_receive", cmd.Flags().Lookup("mqtt-topic-receive"))
	viper.BindPFlag("mqtt_topic_send", cmd.Flags().Lookup("mqtt-topic-send"))

	return cmd
}

func initConfig(configFile string) {
	// Set defaults
	viper.SetDefault("srv6_net", "fc00::/56")
	viper.SetDefault("socket_path", "/var/run/galactic/agent.sock")
	viper.SetDefault("mqtt_url", "tcp://mqtt:1883")
	viper.SetDefault("mqtt_qos", 1)
	viper.SetDefault("mqtt_topic_receive", "galactic/default/receive")
	viper.SetDefault("mqtt_topic_send", "galactic/default/send")

	if configFile != "" {
		viper.SetConfigFile(configFile)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		log.Printf("No config file found - using defaults and environment variables")
	}
}

func runAgent() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Validate SRv6 network configuration
	_, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), "ffffffffffff", "ffff")
	if err != nil {
		log.Fatalf("srv6_net invalid: %v", err)
	}

	// Setup local gRPC server for CNI communication
	var l local.Local
	var r remote.Remote

	l = local.Local{
		SocketPath: viper.GetString("socket_path"),
		RegisterHandler: func(vpc, vpcAttachment string, networks []string) error {
			srv6Endpoint, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), vpc, vpcAttachment)
			if err != nil {
				return err
			}
			if err := srv6.RouteIngressAdd(srv6Endpoint); err != nil {
				return err
			}
			for _, n := range networks {
				log.Printf("REGISTER: network='%s', srv6_endpoint='%s'", n, srv6Endpoint)
				payload, err := proto.Marshal(&remote.Envelope{
					Kind: &remote.Envelope_Register{
						Register: &remote.Register{
							Network:      n,
							Srv6Endpoint: srv6Endpoint,
						},
					},
				})
				if err != nil {
					return err
				}
				r.Send(payload)
			}
			return nil
		},
		DeregisterHandler: func(vpc, vpcAttachment string, networks []string) error {
			srv6Endpoint, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), vpc, vpcAttachment)
			if err != nil {
				return err
			}
			if err := srv6.RouteIngressDel(srv6Endpoint); err != nil {
				return err
			}
			for _, n := range networks {
				log.Printf("DEREGISTER: network='%s', srv6_endpoint='%s'", n, srv6Endpoint)
				payload, err := proto.Marshal(&remote.Envelope{
					Kind: &remote.Envelope_Deregister{
						Deregister: &remote.Deregister{
							Network:      n,
							Srv6Endpoint: srv6Endpoint,
						},
					},
				})
				if err != nil {
					return err
				}
				r.Send(payload)
			}
			return nil
		},
	}

	// Setup MQTT client for router communication
	r = remote.Remote{
		URL:      viper.GetString("mqtt_url"),
		ClientID: viper.GetString("mqtt_clientid"),
		Username: viper.GetString("mqtt_username"),
		Password: viper.GetString("mqtt_password"),
		QoS:      byte(viper.GetInt("mqtt_qos")),
		TopicRX:  viper.GetString("mqtt_topic_receive"),
		TopicTX:  viper.GetString("mqtt_topic_send"),
		ReceiveHandler: func(payload []byte) error {
			envelope := &remote.Envelope{}
			if err := proto.Unmarshal(payload, envelope); err != nil {
				return err
			}
			switch kind := envelope.Kind.(type) {
			case *remote.Envelope_Route:
				log.Printf("ROUTE: status='%s', network='%s', srv6_endpoint='%s', srv6_segments='%s'",
					kind.Route.Status, kind.Route.Network, kind.Route.Srv6Endpoint, kind.Route.Srv6Segments)
				switch kind.Route.Status {
				case remote.Route_ADD:
					if err := srv6.RouteEgressAdd(kind.Route.Network, kind.Route.Srv6Endpoint, kind.Route.Srv6Segments); err != nil {
						return err
					}
				case remote.Route_DELETE:
					if err := srv6.RouteEgressDel(kind.Route.Network, kind.Route.Srv6Endpoint, kind.Route.Srv6Segments); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}

	// Run local and remote servers concurrently
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return l.Serve(ctx)
	})
	g.Go(func() error {
		return r.Run(ctx)
	})

	if err := g.Wait(); err != nil {
		log.Printf("Error: %v", err)
		return err
	}

	log.Printf("Shutdown complete")
	return nil
}
