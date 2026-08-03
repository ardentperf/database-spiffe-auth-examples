# Envoy configuration

This demonstrates a simple Envoy Proxy static bootstrap configuration that proxies TCP to a static cluster representing
a Cassandra node. The listener enforces mTLS and uses SDS to retrieve certificate material from the SPIRE agent. 