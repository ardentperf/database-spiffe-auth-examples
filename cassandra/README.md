# Cassandra SPIFFE Auth Example

## About
This example demonstrates connecting from a Go application to a Cassandra cluster using the [Cassandra Go Client](https://github.com/apache/cassandra-gocql-client/v2).
The application uses a certificate retrieved from a SPIRE agent to authenticate its network connection to an Envoy Proxy
running in front of the Cassandra Cluster. 

The example uses Docker Compose to create a bridge network and attach a number of containers to that bridge, allowing
them to interact with each other over a flat network.

The example runs the following containers:
- [SPIRE Server](./spire/server/)
- [SPIRE Agent](./spire/agent/)
- [Single-node Cassandra Cluster](./docker-compose.cass.yml)
- [Envoy Proxy](./envoy/)
- [Golang client application](./client-go/)

## Usage
- `bash start`: run the example.
- `bash verify`: validate the behavior of the example.
- `bash stop`: clean up the resources created for the example.