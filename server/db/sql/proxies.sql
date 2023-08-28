-- name: CreateProxy :one
INSERT INTO proxies (
  key,
  default_upstream
) VALUES (
  ?, ?
)
RETURNING *;

-- name: GetProxy :one
SELECT *
FROM proxies
WHERE key = ?
LIMIT 1;

-- name: ListProxies :many
SELECT *
FROM proxies
ORDER BY key ASC;

-- name: UpdateProxy :one
UPDATE proxies
SET
  default_upstream = ?,
  updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')
WHERE key = ?
RETURNING *;

-- name: AddProxyEndpoint :exec
INSERT INTO proxies_endpoints (
  proxy_key,
  endpoint_cluster
) VALUES (
  ?,
  ?
);

-- name: GetProxyEndpoints :many
SELECT *
FROM endpoints
WHERE cluster IN (
  SELECT endpoint_cluster
  FROM proxies_endpoints
  WHERE proxy_key = ?
);

-- name: RemoveProxyEndpoint :exec
DELETE FROM proxies_endpoints
WHERE proxy_key = ?
AND endpoint_cluster = ?;

-- name: RemoveAllProxyEndpoints :exec
DELETE FROM proxies_endpoints
WHERE proxy_key = ?;

-- name: DeleteProxy :exec
DELETE FROM proxies
WHERE key = ?
LIMIT 1;
