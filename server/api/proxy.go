package api

import (
	"context"
	"database/sql"

	"github.com/gogo/status"
	"google.golang.org/grpc/codes"

	"github.com/apoxy-dev/proximal/core/log"
	serverdb "github.com/apoxy-dev/proximal/server/db"
	sqlc "github.com/apoxy-dev/proximal/server/db/sql"

	endpointv1 "github.com/apoxy-dev/proximal/api/endpoint/v1"
	proxyv1 "github.com/apoxy-dev/proximal/api/proxy/v1"
)

// ProxyService implements the ProxyServiceServer interface.
type ProxyService struct {
	db *serverdb.DB
}

// NewProxyService returns a new ProxyService.
func NewProxyService(db *serverdb.DB) *ProxyService {
	return &ProxyService{db: db}
}

func proxyFromRow(row sqlc.Proxy) *proxyv1.Proxy {
	return &proxyv1.Proxy{
		Key:             row.Key,
		DefaultEndpoint: row.DefaultUpstream.String,
	}
}

// CreateProxy creates a new proxy.
func (s *ProxyService) CreateProxy(ctx context.Context, req *proxyv1.CreateProxyRequest) (*proxyv1.Proxy, error) {
	log.Infof("creating proxy %s", req.Key)

	tx, err := s.db.Begin()
	if err != nil {
		log.Errorf("failed to begin transaction: %v", err)
		return nil, status.Error(codes.Internal, "failed to create endpoint")
	}
	defer tx.Rollback()
	qtx := s.db.Queries().WithTx(tx)

	proxy, err := s.db.Queries().CreateProxy(ctx, sqlc.CreateProxyParams{
		Key:             req.Key,
		DefaultUpstream: sql.NullString{String: req.DefaultEndpoint, Valid: req.DefaultEndpoint != ""},
	})
	if err != nil {
		log.Errorf("failed to create proxy: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to create proxy")
	}

	for _, e := range req.Endpoints {
		err := qtx.AddProxyEndpoint(ctx, sqlc.AddProxyEndpointParams{
			ProxyKey:        proxy.Key,
			EndpointCluster: e,
		})
		if err != nil {
			log.Errorf("failed to add endpoint %s to proxy %s: %v", e, proxy.Key, err)
			return nil, status.Errorf(codes.Internal, "failed to add endpoint %s to proxy %s", e, proxy.Key)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Errorf("failed to commit transaction: %v", err)
		return nil, status.Error(codes.Internal, "failed to create proxy")
	}

	return proxyFromRow(proxy), nil
}

func (s *ProxyService) ListProxyEndpoints(ctx context.Context, req *proxyv1.ListProxyEndpointsRequest) (*proxyv1.ListProxyEndpointsResponse, error) {
	log.Infof("listing proxy endpoints for proxy %s", req.Key)

	endpoints, err := s.db.Queries().GetProxyEndpoints(ctx, req.Key)
	if err != nil {
		log.Errorf("failed to list proxy endpoints: %v", err)
		return nil, status.Error(codes.Internal, "failed to list proxy endpoints")
	}

	proxy, err := s.db.Queries().GetProxy(ctx, req.Key)
	if err != nil {
		log.Errorf("failed to get proxy: %v", err)
		return nil, status.Error(codes.Internal, "failed to list proxy endpoints")
	}

	epbs := make([]*endpointv1.Endpoint, 0, len(endpoints))
	for _, e := range endpoints {
		addrs, err := s.db.Queries().GetEndpointAddressesByCluster(ctx, e.Cluster)
		if err != nil && err != sql.ErrNoRows {
			return nil, status.Error(codes.Internal, "failed to get endpoint")
		}

		addrpbs := make([]*endpointv1.Address, len(addrs))
		for i, addr := range addrs {
			addrpbs[i] = &endpointv1.Address{
				Host: addr.Host,
				Port: int32(addr.Port),
			}
		}

		epb, err := endpointFromRow(e, proxy.DefaultUpstream.String == e.Cluster, addrpbs)
		if err != nil {
			log.Errorf("failed to convert endpoint: %v", err)
			return nil, status.Error(codes.Internal, "failed to list proxy endpoints")
		}
		epbs = append(epbs, epb)
	}

	return &proxyv1.ListProxyEndpointsResponse{
		Endpoints: epbs,
	}, nil
}