package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"slices"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// The trust domain used by the SPIRE server.
	TrustDomain = "demo.trust.geico"
	// The SPIFFE ID path for the Cassandra node.
	CassandraNodeSPIFFEIDPath = "/cassandra-node"
	// The socket path to the SPIRE agent.
	SpireAgentSocketPath = "unix:///tmp/spire-agent/public/api.sock"
	// The Compose service name and port of the Envoy proxy in front of Cassandra.
	//      This hostname might need to be changed in some environments (cf main README)
	CassandraNodeHost = "envoy:10000"
)

// The server must present a certificate to the GoCQL connection with a SPIFFE ID in this list.
var allowedSpiffeIDs = []spiffeid.ID{
	spiffeid.RequireFromPath(spiffeid.RequireTrustDomainFromString(TrustDomain), CassandraNodeSPIFFEIDPath),
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the workload API client to fetch the X.509 SVID and bundles from the SPIRE agent.
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(SpireAgentSocketPath))
	if err != nil {
		log.Fatalf("failed to create workload API client: %v", err)
	}
	defer client.Close()

	// Create a bundle source to fetch the X.509 bundles from the SPIRE agent.
	bundleSource, err := workloadapi.NewBundleSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(SpireAgentSocketPath)))
	if err != nil {
		log.Fatalf("failed to create bundle source: %v", err)
	}
	defer bundleSource.Close()

	// Retrieve the client's X.509 SVID and bundles from the SPIRE agent.
	svid, err := client.FetchX509SVID(ctx)
	if err != nil {
		log.Fatalf("failed to fetch X.509 context: %v", err)
	}

	// Retrieve the bundles from the SPIRE agent.
	bundleSet, err := client.FetchX509Bundles(ctx)
	if err != nil {
		log.Fatalf("failed to fetch X.509 bundles: %v", err)
	}

	// Get the bundle for the client's trust domain.
	bundle, ok := bundleSet.Get(svid.ID.TrustDomain())
	if !ok {
		log.Fatalf("failed to get bundle for trust domain: %v", svid.ID.TrustDomain())
	}

	// At this point, we've retrieved the client's SPIFFE ID and bundles from the SPIRE agent.
	log.Default().Printf("Retrieved SPIFFE ID from socket with SPIFFE ID: %s", svid.ID.String())

	// Create a new GoCQL cluster to connect to the Cassandra node.
	cluster := gocql.NewCluster(CassandraNodeHost)
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: "cassandra",
		Password: "cassandra",
	}

	// Create a certificate pool to add the X.509 authorities from the bundle.
	rootCAs := x509.NewCertPool()
	for _, authority := range bundle.X509Authorities() {
		rootCAs.AddCert(authority)
	}

	// Configure the GoCQL connection to use the X.509 authorities and the client's certificate.
	cluster.SslOpts = &gocql.SslOptions{
		Config: &tls.Config{
			RootCAs: rootCAs,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{svid.Certificates[0].Raw},
					PrivateKey:  svid.PrivateKey,
				},
			},
			// We don't verify the server's certificate with the standard library TLS verification
			// because we're using mTLS and the server will present a certificate with a SPIFFE ID in the URI SAN list.
			InsecureSkipVerify: true,
			// Verify the server's certificate with the SPIFFE ID in the URI SAN list.
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				id, _, err := x509svid.ParseAndVerify(rawCerts, bundleSource)
				if err != nil {
					return err
				}

				if !slices.Contains(allowedSpiffeIDs, id) {
					return fmt.Errorf("invalid SPIFFE ID: %s", id.String())
				}

				log.Default().Printf("Verified SPIFFE ID: %s", id.String())

				return nil
			},
		},
		EnableHostVerification: false,
	}

	// Create a new GoCQL session to connect to the Cassandra node.
	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatalf("failed to create session: %v", err)
	}
	defer session.Close()

	// At this point, we've connected to the envoy proxy, completed the mTLS handshake and
	// both parties have verified the other's identity and authorized the connection.
	//
	// Now we can execute a query to the Cassandra node over the open connection, since
	// Envoy will reverse proxy it to the Cassandra node.
	log.Default().Println("Connected to Cassandra")

	// Simulate a simple query to the Cassandra node.
	query := session.Query("SELECT * FROM system.local")
	iter := query.Iter()
	m := make(map[string]any)
	for iter.MapScan(m) {
		log.Default().Printf("Retrieved row from system.local:")
		for key, value := range m {
			log.Default().Printf("  column %s: value %v", key, value)
		}
	}

	if err := iter.Close(); err != nil {
		log.Fatalf("failed to close iterator: %v", err)
	}

	if len(m) > 0 {
		log.Default().Println("Successfully connected to Cassandra and retrieved row from system.local")
		os.Exit(0)
	} else {
		log.Default().Println("Failed to connect to Cassandra or no rows retrieved from system.local")
		os.Exit(1)
	}
}
