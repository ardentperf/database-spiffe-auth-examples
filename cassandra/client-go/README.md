# Cassandra Client

This is a simple Go program using the `github.com/apache/cassandra-gocql-driver/v2` client to connect to a Cassandra cluster.
The client uses SPIRE certificates to encrypt and authenticate the transport, and validates that the Cassandra protocol
can successfully decouple mTLS transport from authentication.