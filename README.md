# SPIFFE Auth Examples
This repo contains examples for demonstrating the use of SPIFFE IDs in various scenarios. 

## Examples
- [Cassandra Client using mTLS as transport encryption terminated at Envoy Proxy](./cassandra/)
- [PostgreSQL Client using transparent Envoy sidecar mTLS proxy with Postgres L7 filter](./postgres/)

### Docker networking note

The SPIRE Agent connects to the SPIRE Server at `spire-server:8081`, using Docker Compose's
internal DNS. This is the correct address on Linux. Depending on the docker environment,
`server_address` might need to be changed to some other value like `host.docker.internal`. This
also applies to `CassandraNodeHost`.
