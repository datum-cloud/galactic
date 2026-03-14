package underlay

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/client-go/kubernetes"
)

// Config holds the configuration for the underlay route controller.
type Config struct {
	GoBGPAddr string // e.g. "127.0.0.1:50051"
	LocalNode string // this node's name (from NODE_NAME env)
	SRv6Net   string // this node's SRv6 /48 prefix (e.g. "2001:db8:ff01::/48")
	BGPPort   int32  // GoBGP listen port (e.g. 1790)
	BGPAS     uint32 // BGP AS number (e.g. 65000)
}

// Controller manages BGP-based underlay route distribution by connecting to
// a local GoBGP instance via gRPC, configuring peers, advertising this node's
// SRv6 prefix, and programming netlink routes for peer prefixes.
type Controller struct {
	cfg       Config
	k8sClient kubernetes.Interface
}

// NewController creates a new underlay route controller.
func NewController(cfg Config, k8sClient kubernetes.Interface) *Controller {
	return &Controller{cfg: cfg, k8sClient: k8sClient}
}

// Run starts the controller. It blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	conn, err := c.connectGoBGP(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := gobgpapi.NewGobgpApiClient(conn)

	localIP, err := LocalNodeIPv6(ctx, c.k8sClient, c.cfg.LocalNode)
	if err != nil {
		return fmt.Errorf("get local node IP: %w", err)
	}
	log.Printf("underlay: local node %s IP %s", c.cfg.LocalNode, localIP)

	peers, err := ListPeerAddresses(ctx, c.k8sClient, c.cfg.LocalNode)
	if err != nil {
		return fmt.Errorf("list peer addresses: %w", err)
	}
	log.Printf("underlay: discovered %d peers", len(peers))

	for _, p := range peers {
		if err := c.addPeer(ctx, client, p, localIP); err != nil {
			return fmt.Errorf("add peer %s: %w", p.Name, err)
		}
		log.Printf("underlay: added peer %s (%s)", p.Name, p.Address)
	}

	if err := c.advertiseSRv6Prefix(ctx, client, localIP); err != nil {
		return fmt.Errorf("advertise prefix: %w", err)
	}
	log.Printf("underlay: advertising %s", c.cfg.SRv6Net)

	return c.watchAndProgram(ctx, client)
}

func (c *Controller) connectGoBGP(ctx context.Context) (*grpc.ClientConn, error) {
	var conn *grpc.ClientConn
	var err error

	for attempt := 0; ; attempt++ {
		conn, err = grpc.NewClient(
			c.cfg.GoBGPAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			_, pingErr := gobgpapi.NewGobgpApiClient(conn).GetBgp(ctx, &gobgpapi.GetBgpRequest{})
			if pingErr == nil {
				return conn, nil
			}
			conn.Close()
			err = pingErr
		}

		if attempt >= 30 {
			return nil, fmt.Errorf("connect to GoBGP at %s after %d attempts: %w", c.cfg.GoBGPAddr, attempt, err)
		}

		log.Printf("underlay: waiting for GoBGP at %s (attempt %d): %v", c.cfg.GoBGPAddr, attempt+1, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Controller) addPeer(ctx context.Context, client gobgpapi.GobgpApiClient, peer PeerInfo, localIP net.IP) error {
	_, err := client.AddPeer(ctx, &gobgpapi.AddPeerRequest{
		Peer: &gobgpapi.Peer{
			Conf: &gobgpapi.PeerConf{
				NeighborAddress: peer.Address.String(),
				PeerAsn:         c.cfg.BGPAS,
			},
			Transport: &gobgpapi.Transport{
				LocalAddress: localIP.String(),
			},
			AfiSafis: []*gobgpapi.AfiSafi{
				{
					Config: &gobgpapi.AfiSafiConfig{
						Family: &gobgpapi.Family{
							Afi:  gobgpapi.Family_AFI_IP6,
							Safi: gobgpapi.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	return err
}

func (c *Controller) advertiseSRv6Prefix(ctx context.Context, client gobgpapi.GobgpApiClient, localIP net.IP) error {
	_, prefix, err := net.ParseCIDR(c.cfg.SRv6Net)
	if err != nil {
		return fmt.Errorf("parse SRv6 prefix %s: %w", c.cfg.SRv6Net, err)
	}

	prefixLen, _ := prefix.Mask.Size()

	// Marshal IPv6 prefix as NLRI
	nlri, err := anypb.New(&gobgpapi.IPAddressPrefix{
		PrefixLen: uint32(prefixLen),
		Prefix:    prefix.IP.String(),
	})
	if err != nil {
		return fmt.Errorf("marshal NLRI: %w", err)
	}

	// Marshal origin attribute (IGP)
	origin, err := anypb.New(&gobgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return fmt.Errorf("marshal origin: %w", err)
	}

	// For IPv6, next-hop goes in MP_REACH_NLRI rather than NEXT_HOP attribute
	mpReach, err := anypb.New(&gobgpapi.MpReachNLRIAttribute{
		Family: &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP6,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
		NextHops: []string{localIP.String()},
		Nlris:    []*anypb.Any{nlri},
	})
	if err != nil {
		return fmt.Errorf("marshal mp_reach: %w", err)
	}

	_, err = client.AddPath(ctx, &gobgpapi.AddPathRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Path: &gobgpapi.Path{
			Family: &gobgpapi.Family{
				Afi:  gobgpapi.Family_AFI_IP6,
				Safi: gobgpapi.Family_SAFI_UNICAST,
			},
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, mpReach},
		},
	})
	return err
}

func (c *Controller) watchAndProgram(ctx context.Context, client gobgpapi.GobgpApiClient) error {
	knownPrefixes := make(map[string]net.IP)

	stream, err := client.WatchEvent(ctx, &gobgpapi.WatchEventRequest{
		Table: &gobgpapi.WatchEventRequest_Table{
			Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
				{
					Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
					Init: true,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("watch event: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("watch recv: %w", err)
			}
		}

		table := resp.GetTable()
		if table == nil {
			continue
		}

		for _, path := range table.Paths {
			if path.Family == nil || path.Family.Afi != gobgpapi.Family_AFI_IP6 || path.Family.Safi != gobgpapi.Family_SAFI_UNICAST {
				continue
			}

			prefix, nextHop, err := extractPrefixAndNextHop(path)
			if err != nil {
				log.Printf("underlay: skip path: %v", err)
				continue
			}

			_, ownPrefix, _ := net.ParseCIDR(c.cfg.SRv6Net)
			if ownPrefix != nil && prefix.String() == ownPrefix.String() {
				continue
			}

			if path.IsWithdraw {
				log.Printf("underlay: DEL route %s", prefix)
				if err := DelRoute(prefix); err != nil {
					log.Printf("underlay: del route %s: %v", prefix, err)
				}
				delete(knownPrefixes, prefix.String())
			} else {
				log.Printf("underlay: ADD route %s via %s", prefix, nextHop)
				if err := AddRoute(prefix, nextHop); err != nil {
					log.Printf("underlay: add route %s via %s: %v", prefix, nextHop, err)
				}
				knownPrefixes[prefix.String()] = nextHop
			}
		}
	}
}

func extractPrefixAndNextHop(path *gobgpapi.Path) (*net.IPNet, net.IP, error) {
	// Use apiutil to get the native NLRI
	nlri, err := apiutil.GetNativeNlri(path)
	if err != nil {
		return nil, nil, fmt.Errorf("get native NLRI: %w", err)
	}

	_, ipNet, err := net.ParseCIDR(nlri.String())
	if err != nil {
		return nil, nil, fmt.Errorf("parse prefix %s: %w", nlri.String(), err)
	}

	// Extract next-hop from path attributes
	attrs, err := apiutil.GetNativePathAttributes(path)
	if err != nil {
		return nil, nil, fmt.Errorf("get native path attrs: %w", err)
	}

	var nextHop net.IP
	for _, attr := range attrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			nextHop = a.Value
		case *bgp.PathAttributeMpReachNLRI:
			if len(a.Nexthop) > 0 {
				nextHop = a.Nexthop
			}
		}
	}
	if nextHop == nil {
		return nil, nil, fmt.Errorf("no next-hop found in path attributes")
	}

	return ipNet, nextHop, nil
}
