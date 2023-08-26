CREATE TABLE proxies (
  key               VARCHAR(255) PRIMARY KEY,
  default_upstream  VARCHAR(255),
  created_at        DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
  updated_at        DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
  FOREIGN KEY (default_upstream) REFERENCES endpoints(cluster)
);

CREATE TABLE proxies_endpoints (
  proxy_key         VARCHAR(255) NOT NULL,
  endpoint_cluster  VARCHAR(255) NOT NULL,
  PRIMARY KEY (proxy_key, endpoint_cluster),
  FOREIGN KEY (proxy_key) REFERENCES proxy(key),
  FOREIGN KEY (endpoint_cluster) REFERENCES endpoints(cluster)
);
