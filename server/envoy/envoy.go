package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	accessloggrpcv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	dfpclustersv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	tapv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/tap/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httptapv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/tap/v3"
	httpwasmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	httpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	getaddrinfov3 "github.com/envoyproxy/go-control-plane/envoy/extensions/network/dns_resolver/getaddrinfo/v3"
	intupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/internal_upstream/v3"
	rawbufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/raw_buffer/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	wasmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	clusterservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservicev3 "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	metadatav3 "github.com/envoyproxy/go-control-plane/envoy/type/metadata/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/gogo/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/apoxy-dev/proximal/core/log"

	endpointv1 "github.com/apoxy-dev/proximal/api/endpoint/v1"
	middlewarev1 "github.com/apoxy-dev/proximal/api/middleware/v1"
)

const (
	wgEncapListener = "wg_encap"

	defaultUpstreamCluster = "default_upstream"
	dynamicUpstreamCluster = "dynamic_upstream"
	controlUpstreamCluster = "control_upstream"
	wgProxyCluster         = "wg_proxy"

	xdsClusterName = "xds_cluster"
	alsClusterName = "als_cluster"

	xApoxyMagicHeader = "x-apoxy-magic"

	tunnelMetadataKey = "tunnel"
)

// SnapshotManager is responsible for managing the Envoy snapshot cache.
type SnapshotManager struct {
	listenHost   string
	listenPort   int
	syncInterval time.Duration
	buildBaseDir string

	mSvc      middlewarev1.MiddlewareServiceClient
	eSvc      endpointv1.EndpointServiceClient
	xdsServer xds.Server
	cache     cache.SnapshotCache

	controlDomain string
	fileHashes    map[string]string
	syncCh        chan struct{}
}

// NewSnapshotManager returns a new *SnapshotManager.
func NewSnapshotManager(
	ctx context.Context,
	mSvc middlewarev1.MiddlewareServiceClient,
	eSvc endpointv1.EndpointServiceClient,
	buildBaseDir string,
	host string, port int,
	syncInterval time.Duration,
	controlDomain string,
) *SnapshotManager {
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
	return &SnapshotManager{
		listenHost:    host,
		listenPort:    port,
		syncInterval:  syncInterval,
		mSvc:          mSvc,
		eSvc:          eSvc,
		buildBaseDir:  buildBaseDir,
		xdsServer:     xds.NewServer(ctx, snapshotCache, nil),
		cache:         snapshotCache,
		controlDomain: controlDomain,
		fileHashes:    make(map[string]string),
		syncCh:        make(chan struct{}),
	}
}

func dnsLookupFamilyFromProto(f endpointv1.Endpoint_DNSLookupFamily) clusterv3.Cluster_DnsLookupFamily {
	switch f {
	case endpointv1.Endpoint_V4_ONLY:
		return clusterv3.Cluster_V4_ONLY
	case endpointv1.Endpoint_V6_ONLY:
		return clusterv3.Cluster_V6_ONLY
	case endpointv1.Endpoint_V4_FIRST:
		return clusterv3.Cluster_V4_PREFERRED
	case endpointv1.Endpoint_V6_FIRST:
		return clusterv3.Cluster_AUTO
	default:
		return clusterv3.Cluster_AUTO
	}
}

func (s *SnapshotManager) clusterResources(clusterID string, es []*endpointv1.Endpoint) ([]types.Resource, error) {
	var clusters []types.Resource

	tlspb, _ := anypb.New(&tlsv3.UpstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					TrustedCa: &core.DataSource{
						Specifier: &core.DataSource_Filename{
							Filename: "/etc/ssl/certs/ca-certificates.crt",
						},
					},
				},
			},
		},
	})
	getAddrDNS, _ := anypb.New(&getaddrinfov3.GetAddrInfoDnsResolverConfig{})
	dfpcls, _ := anypb.New(&dfpclustersv3.ClusterConfig{
		ClusterImplementationSpecifier: &dfpclustersv3.ClusterConfig_DnsCacheConfig{
			DnsCacheConfig: &dfpcommonv3.DnsCacheConfig{
				Name:            "dynamic_forward_proxy_cache_config",
				DnsLookupFamily: clusterv3.Cluster_V4_PREFERRED,
				TypedDnsResolverConfig: &core.TypedExtensionConfig{
					Name:        "envoy.network.dns_resolver.getaddrinfo",
					TypedConfig: getAddrDNS,
				},
			},
		},
	})
	clusters = append(clusters, &clusterv3.Cluster{
		Name:           dynamicUpstreamCluster,
		ConnectTimeout: durationpb.New(5 * time.Second),
		LbPolicy:       clusterv3.Cluster_CLUSTER_PROVIDED,
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: tlspb,
			},
		},
		ClusterDiscoveryType: &clusterv3.Cluster_ClusterType{
			ClusterType: &clusterv3.Cluster_CustomClusterType{
				Name:        "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: dfpcls,
			},
		},
	})

	wgProxyHost := &endpointv3.Endpoint{
		Address: &core.Address{
			Address: &core.Address_Pipe{
				Pipe: &core.Pipe{
					Path: fmt.Sprintf("/tmp/wg-%s.sock", clusterID),
				},
			},
		},
	}
	clusters = append(clusters, &clusterv3.Cluster{
		Name:           wgProxyCluster,
		ConnectTimeout: durationpb.New(5 * time.Second),
		LbPolicy:       clusterv3.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: wgProxyCluster,
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: wgProxyHost,
							},
						},
					},
				},
			},
		},
	})

	for _, e := range es {
		log.Debugf("adding cluster: %v", e)

		cl := &clusterv3.Cluster{
			Name:            e.Cluster,
			ConnectTimeout:  durationpb.New(5 * time.Second),
			DnsLookupFamily: dnsLookupFamilyFromProto(e.DnsLookupFamily),
		}
		if e.UseTls {
			tlspb, _ := anypb.New(&tlsv3.UpstreamTlsContext{})
			cl.TransportSocket = &core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: tlspb,
				},
			}
		} else if e.IsPrivate {
			rawBuffer, _ := anypb.New(&rawbufferv3.RawBuffer{})
			intUpstream, _ := anypb.New(&intupstreamv3.InternalUpstreamTransport{
				PassthroughMetadata: []*intupstreamv3.InternalUpstreamTransport_MetadataValueSource{
					{
						Kind: &metadatav3.MetadataKind{
							Kind: &metadatav3.MetadataKind_Host_{
								Host: &metadatav3.MetadataKind_Host{},
							},
						},
						Name: tunnelMetadataKey,
					},
				},
				TransportSocket: &core.TransportSocket{
					Name: "envoy.transport_sockets.raw_buffer",
					ConfigType: &core.TransportSocket_TypedConfig{
						TypedConfig: rawBuffer,
					},
				},
			})

			cl.TransportSocket = &core.TransportSocket{
				Name: "envoy.transport_sockets.internal_upstream",
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: intUpstream,
				},
			}
		}

		if e.Status == nil {
			log.Warnf("endpoint %v has no status", e)
			continue
		}

		// For private endpoints, still set the cluster discovery type to STATIC
		// so that upstream is considered healthy.
		// DNS resolution will be done by the WireGuard proxy.
		if e.Status.IsDomain && !e.IsPrivate {
			cl.ClusterDiscoveryType = &clusterv3.Cluster_Type{
				Type: clusterv3.Cluster_STRICT_DNS,
			}
		} else {
			cl.ClusterDiscoveryType = &clusterv3.Cluster_Type{
				Type: clusterv3.Cluster_STATIC,
			}
		}

		cl.LoadAssignment = &endpointv3.ClusterLoadAssignment{
			ClusterName: e.Cluster,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: make([]*endpointv3.LbEndpoint, len(e.Addresses)),
			}},
		}
		for i, addr := range e.Addresses {
			// For private endpoints, we need to add the tunnel metadata to the endpoint
			// and send it to internal listener that will tunnel it through the WireGuard
			// proxy.
			if e.IsPrivate {
				cl.LoadAssignment.Endpoints[0].LbEndpoints[i] = &endpointv3.LbEndpoint{
					Metadata: &core.Metadata{
						FilterMetadata: map[string]*structpb.Struct{
							tunnelMetadataKey: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"address": {
										Kind: &structpb.Value_StringValue{
											StringValue: fmt.Sprintf("%s:%d", addr.Host, addr.Port),
										},
									},
								},
							},
						},
					},
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
						Endpoint: &endpointv3.Endpoint{
							Address: &core.Address{
								Address: &core.Address_EnvoyInternalAddress{
									EnvoyInternalAddress: &core.EnvoyInternalAddress{
										AddressNameSpecifier: &core.EnvoyInternalAddress_ServerListenerName{
											ServerListenerName: wgEncapListener,
										},
									},
								},
							},
						},
					},
				}
			} else {
				cl.LoadAssignment.Endpoints[0].LbEndpoints[i] = &endpointv3.LbEndpoint{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
						Endpoint: &endpointv3.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Address: addr.Host,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: uint32(addr.Port),
										},
									},
								},
							},
						},
					},
				}
			}
		}

		clusters = append(clusters, cl)

		if e.DefaultUpstream {
			log.Debugf("adding default upstream: %v", e)
			def := &clusterv3.Cluster{
				Name:                 defaultUpstreamCluster,
				ConnectTimeout:       cl.ConnectTimeout,
				ClusterDiscoveryType: cl.ClusterDiscoveryType,
				DnsLookupFamily:      dnsLookupFamilyFromProto(e.DnsLookupFamily),
				LoadAssignment: &endpointv3.ClusterLoadAssignment{
					ClusterName: defaultUpstreamCluster,
					Endpoints:   cl.LoadAssignment.Endpoints,
				},
				TransportSocket: cl.TransportSocket,
			}
			clusters = append(clusters, def)
		}
	}

	return clusters, nil
}

func (s *SnapshotManager) httpConnectionManager(ctx context.Context, mds []*middlewarev1.Middleware) (*anypb.Any, error) {
	var filters []*httpproxyv3.HttpFilter
	for _, middleware := range mds {
		log.Debugf("adding middleware %s", middleware.Slug)

		switch middleware.Status {
		case middlewarev1.Middleware_READY, middlewarev1.Middleware_PENDING_READY:
		default:
			log.Infof("%s is not ready", middleware.Slug)
			continue
		}

		if middleware.LiveBuildSha == "" {
			log.Warnf("%s has no live build", middleware.Slug)
			continue
		}
		wasmOut := filepath.Join(s.buildBaseDir, middleware.Slug, middleware.LiveBuildSha, "wasm.out")
		if _, err := os.Stat(wasmOut); os.IsNotExist(err) {
			log.Warnf("%s wasm does not exist", middleware.Slug)
			continue
		}

		sha256, ok := s.fileHashes[wasmOut]
		var err error
		if !ok {
			sha256, err = CalculateFileSHA256(wasmOut)
			if err != nil {
				return nil, err
			}
			s.fileHashes[wasmOut] = sha256
		}

		buildPath := filepath.Join(middleware.Slug, middleware.LiveBuildSha, "wasm.out")

		wasmConfig, err := anypb.New(&wrapperspb.StringValue{
			Value: middleware.RuntimeParams.ConfigString,
		})
		if err != nil {
			return nil, err
		}
		wpb, _ := anypb.New(&httpwasmv3.Wasm{
			Config: &wasmv3.PluginConfig{
				Vm: &wasmv3.PluginConfig_VmConfig{
					VmConfig: &wasmv3.VmConfig{
						Runtime: "envoy.wasm.runtime.v8",
						Code: &core.AsyncDataSource{
							Specifier: &core.AsyncDataSource_Remote{
								Remote: &core.RemoteDataSource{
									HttpUri: &core.HttpUri{
										Uri: fmt.Sprintf("https://%s/wasm_builds/%s", s.controlDomain, buildPath),
										HttpUpstreamType: &core.HttpUri_Cluster{
											Cluster: controlUpstreamCluster,
										},
										Timeout: durationpb.New(10 * time.Second),
									},
									Sha256: sha256,
								},
							},
						},
					},
				},
				Configuration: wasmConfig,
			},
		})
		filters = append(filters, &httpproxyv3.HttpFilter{
			Name: wellknown.HTTPWasm,
			ConfigType: &httpproxyv3.HttpFilter_TypedConfig{
				TypedConfig: wpb,
			},
		})
	}

	tpb, err := anypb.New(&httptapv3.Tap{
		CommonConfig: &tapv3.CommonExtensionConfig{
			ConfigType: &tapv3.CommonExtensionConfig_AdminConfig{
				AdminConfig: &tapv3.AdminConfig{
					ConfigId: "http_logs",
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	filters = append(filters, &httpproxyv3.HttpFilter{
		Name: resource.APITypePrefix + "envoy.extensions.filters.http.tap.v3.Tap",
		ConfigType: &httpproxyv3.HttpFilter_TypedConfig{
			TypedConfig: tpb,
		},
	})

	rpb, err := anypb.New(&routerv3.Router{})
	if err != nil {
		return nil, err
	}
	filters = append(filters, &httpproxyv3.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &httpproxyv3.HttpFilter_TypedConfig{
			TypedConfig: rpb,
		},
	})

	alspb, err := anypb.New(&accessloggrpcv3.HttpGrpcAccessLogConfig{
		CommonConfig: &accessloggrpcv3.CommonGrpcAccessLogConfig{
			LogName:             "http_log",
			TransportApiVersion: resource.DefaultAPIVersion,
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: alsClusterName,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	hcm := &httpproxyv3.HttpConnectionManager{
		CodecType:  httpproxyv3.HttpConnectionManager_AUTO,
		StatPrefix: "ingress_http",
		RouteSpecifier: &httpproxyv3.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route_v3.RouteConfiguration{
				Name: "local_route",
				VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
					Name:    defaultUpstreamCluster,
					Domains: []string{"*"},
					Routes: []*envoy_config_route_v3.Route{
						{
							Match: &envoy_config_route_v3.RouteMatch{
								PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
									Prefix: "/",
								},
								Headers: []*envoy_config_route_v3.HeaderMatcher{{
									Name: xApoxyMagicHeader,
									HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_PresentMatch{
										PresentMatch: true,
									},
								}},
							},
							Action: &envoy_config_route_v3.Route_Route{
								Route: &envoy_config_route_v3.RouteAction{
									ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
										Cluster: dynamicUpstreamCluster,
									},
								},
							},
						},
						{
							Match: &envoy_config_route_v3.RouteMatch{
								PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
									Prefix: "/",
								},
							},
							Action: &envoy_config_route_v3.Route_Route{
								Route: &envoy_config_route_v3.RouteAction{
									ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
										Cluster: defaultUpstreamCluster,
									},
									HostRewriteSpecifier: &envoy_config_route_v3.RouteAction_AutoHostRewrite{
										AutoHostRewrite: &wrapperspb.BoolValue{
											Value: true,
										},
									},
								},
							},
						},
					},
				}},
			},
		},
		HttpFilters: filters,
		AccessLog: []*accesslogv3.AccessLog{{
			Name: wellknown.HTTPGRPCAccessLog,
			ConfigType: &accesslogv3.AccessLog_TypedConfig{
				TypedConfig: alspb,
			},
		}},
	}
	return anypb.New(hcm)
}

func (s *SnapshotManager) listenerResources(ctx context.Context, nodeID string, mds []*middlewarev1.Middleware) ([]types.Resource, error) {
	lst := &listenerv3.Listener{
		Name:    "main",
		Address: &core.Address{},
	}
	if s.listenHost == "" { // unix domain socket
		lst.Address.Address = &core.Address_Pipe{
			Pipe: &core.Pipe{
				Path: fmt.Sprintf("/tmp/%s.sock", nodeID),
			},
		}
	} else {
		lst.Address.Address = &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.SocketAddress_TCP,
				Address:  s.listenHost,
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: uint32(s.listenPort),
				},
			},
		}
	}

	hcmpb, err := s.httpConnectionManager(ctx, mds)
	if err != nil {
		return nil, fmt.Errorf("failed to generate http connection manager: %v", err)
	}

	lst.FilterChains = []*listenerv3.FilterChain{{
		Filters: []*listenerv3.Filter{{
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &listenerv3.Filter_TypedConfig{
				TypedConfig: hcmpb,
			},
		}},
	}}

	tcpProxy, err := anypb.New(&tcpproxyv3.TcpProxy{
		StatPrefix: "ingress_tcp",
		ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{
			Cluster: wgProxyCluster,
		},
		TunnelingConfig: &tcpproxyv3.TcpProxy_TunnelingConfig{
			Hostname: "%DYNAMIC_METADATA(tunnel:address)%",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate tcp proxy: %v", err)
	}

	intLst := &listenerv3.Listener{
		Name: wgEncapListener,
		ListenerSpecifier: &listenerv3.Listener_InternalListener{
			InternalListener: &listenerv3.Listener_InternalListenerConfig{},
		},
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name: "tcp_proxy",
				ConfigType: &listenerv3.Filter_TypedConfig{
					TypedConfig: tcpProxy,
				},
			}},
		}},
	}

	return []types.Resource{lst, intLst}, nil
}

func (s *SnapshotManager) filterEndpoints(endpoints []*endpointv1.Endpoint, node *core.Node) ([]*endpointv1.Endpoint, error) {
	var filtered []*endpointv1.Endpoint
EndpointLoop:
	for _, ep := range endpoints {
		// if no proxy filter is defined, accept all endpoints.
		if ep.ProxyFilter == nil || ep.ProxyFilter.MatcherList == nil {
			filtered = append(filtered, ep)
			continue
		}
		// if no metadata is defined but a proxy filter is defined, there is no match.
		if node.Metadata == nil || node.Metadata.Fields == nil {
			continue
		}

		for _, m := range ep.ProxyFilter.MatcherList.Matchers {
			if !strings.HasPrefix(m.MetadataField, "envoy.") {
				continue
			}
			mf := strings.TrimLeft(m.MetadataField, "envoy.")
			if v := node.Metadata.Fields[mf]; v != nil && v.GetStringValue() == m.Value {
				filtered = append(filtered, ep)
				continue EndpointLoop
			}
		}
	}
	return filtered, nil
}

func (s *SnapshotManager) sync(ctx context.Context) error {
	id := time.Now().Unix()

	mrsp, err := s.mSvc.InternalList(ctx, &emptypb.Empty{})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Infof("no middlewares found, skipping snapshot (id:%d)", id)
			return nil
		}
		return fmt.Errorf("failed to list middlewares: %v", err)
	}

	ersp, err := s.eSvc.InternalListEndpoints(ctx, &emptypb.Empty{})
	fmt.Println("ersp", ersp)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Infof("no endpoints found, skipping snapshot (id:%d)", id)
			return nil
		}
		return fmt.Errorf("failed to list endpoints: %v", err)
	}

	// Append the control upstream cluster.
	ersp.Endpoints = append(ersp.GetEndpoints(), &endpointv1.Endpoint{
		Cluster:         controlUpstreamCluster,
		DefaultUpstream: false,
		Status: &endpointv1.EndpointStatus{
			IsDomain: true,
		},
		Addresses: []*endpointv1.Address{{
			Host: s.controlDomain,
			Port: 443,
		}},
		DnsLookupFamily: endpointv1.Endpoint_V4_ONLY,
		UseTls:          true,
	})

	nodeIDs := s.cache.GetStatusKeys()
	for _, nodeID := range nodeIDs {
		info := s.cache.GetStatusInfo(nodeID)
		nodepb := info.GetNode()
		if nodepb == nil {
			log.Warnf("no node found for nodeID:%v", nodeID)
		}

		es, err := s.filterEndpoints(ersp.GetEndpoints(), nodepb)
		if err != nil {
			return err
		}

		log.Infof("filtered endpoints id:%d for node:%v with %d endpoints", id, nodeID, len(es))

		cls, err := s.clusterResources(nodepb.Cluster, es)
		if err != nil {
			return err
		}

		ls, err := s.listenerResources(ctx, nodeID, mrsp.GetMiddlewares())
		if err != nil {
			return err
		}

		log.Infof("syncing snapshot id:%d for node:%v with %d endpoints", id, nodeID, len(es))

		snapshot, err := cache.NewSnapshot(
			fmt.Sprintf("%d.0", id),
			map[resource.Type][]types.Resource{
				resource.ClusterType:  cls,
				resource.ListenerType: ls,
			},
		)
		if err != nil {
			return err
		}
		if err := snapshot.Consistent(); err != nil {
			return err
		}

		if err = s.cache.SetSnapshot(ctx, nodeID, snapshot); err != nil {
			log.Warnf("error setting snapshot for node %s: %v", nodeID, err)
		}
	}

	log.Infof("successfully synced snapshot (id:%d) for %d endpoints", id, len(ersp.GetEndpoints()))

	return nil
}

// Run starts a blocking sync loop that updates the snapshot cache at the
// configured interval.
func (s *SnapshotManager) Run(ctx context.Context) error {
	for {
		select {
		case <-s.syncCh:
			if err := s.sync(ctx); err != nil {
				log.Errorf("error syncing snapshot: %v", err)
			}
		case <-time.After(s.syncInterval):
			if err := s.sync(ctx); err != nil {
				log.Errorf("error syncing snapshot: %v", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	panic("unreachable")
}

func (s *SnapshotManager) TriggerUpdate(ctx context.Context) error {
	select {
	case s.syncCh <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (m *SnapshotManager) RegisterXDS(srv *grpc.Server) {
	discoveryservicev3.RegisterAggregatedDiscoveryServiceServer(srv, m.xdsServer)
	endpointservicev3.RegisterEndpointDiscoveryServiceServer(srv, m.xdsServer)
	clusterservicev3.RegisterClusterDiscoveryServiceServer(srv, m.xdsServer)
	routeservicev3.RegisterRouteDiscoveryServiceServer(srv, m.xdsServer)
	listenerservicev3.RegisterListenerDiscoveryServiceServer(srv, m.xdsServer)
}

func (s *SnapshotManager) Shutdown() {
	s.cache = nil
}

// CalculateFileSHA256 computes the SHA-256 hash of a file.
func CalculateFileSHA256(filePath string) (string, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Create a new SHA-256 hasher
	hasher := sha256.New()

	// Copy the file's contents into the hasher
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	// Get the final hash and convert it to a hexadecimal string
	hash := hasher.Sum(nil)
	hashString := hex.EncodeToString(hash)

	return hashString, nil
}
