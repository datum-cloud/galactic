package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"google.golang.org/protobuf/proto"

	"github.com/datum-cloud/galactic-agent/api/local"
	"github.com/datum-cloud/galactic-agent/api/remote"
	"github.com/datum-cloud/galactic-agent/srv6"
	"github.com/datum-cloud/galactic-common/util"
)

var configFile string

func initConfig() {
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
		log.Printf("No config file found - using defaults.")
	}
}

var (
	l local.Local
	r remote.Remote
)

func main() {
	cmd := &cobra.Command{
		Use:   "galactic-agent",
		Short: "Galactic Agent",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initConfig()
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop() //nolint:errcheck

			_, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), "ffffffffffff", "ffff")
			if err != nil {
				log.Fatalf("srv6_endpoint invalid: %v", err)
			}

			l = local.Local{
				SocketPath: viper.GetString("socket_path"),
				RegisterHandler: func(vpc, vpcAttachment string, networks []string) error {
					srv6_endpoint, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), vpc, vpcAttachment)
					if err != nil {
						return err
					}
					if err := srv6.RouteIngressAdd(srv6_endpoint); err != nil {
						return err
					}
					for _, n := range networks {
						log.Printf("REGISTER: network='%s', srv6_endpoint='%s'", n, srv6_endpoint)
						payload, err := proto.Marshal(&remote.Envelope{
							Kind: &remote.Envelope_Register{
								Register: &remote.Register{
									Network:      n,
									Srv6Endpoint: srv6_endpoint,
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
					srv6_endpoint, err := util.EncodeSRv6Endpoint(viper.GetString("srv6_net"), vpc, vpcAttachment)
					if err != nil {
						return err
					}
					if err := srv6.RouteIngressDel(srv6_endpoint); err != nil {
						return err
					}
					for _, n := range networks {
						log.Printf("DEREGISTER: network='%s', srv6_endpoint='%s'", n, srv6_endpoint)
						payload, err := proto.Marshal(&remote.Envelope{
							Kind: &remote.Envelope_Deregister{
								Deregister: &remote.Deregister{
									Network:      n,
									Srv6Endpoint: srv6_endpoint,
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
						log.Printf("ROUTE: status='%s', network='%s', srv6_endpoint='%s', srv6_segments='%s'", kind.Route.Status, kind.Route.Network, kind.Route.Srv6Endpoint, kind.Route.Srv6Segments)
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

			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				return l.Serve(ctx)
			})
			g.Go(func() error {
				return r.Run(ctx)
			})
			if err := g.Wait(); err != nil {
				log.Printf("Error: %v", err)
			}
			log.Printf("Shutdown")
		},
	}
	cmd.PersistentFlags().StringVar(&configFile, "config", "", "config file")
	cmd.SetArgs(os.Args[1:])
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Execution failed: %v", err)
	}
}
