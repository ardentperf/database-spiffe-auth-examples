package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

const (
	// The Go app connects to the client-side Envoy sidecar, which it believes is a regular
	// Postgres server. Envoy transparently proxies the connection over an mTLS tunnel to
	// the server-side Envoy, which terminates TLS and forwards plaintext to the real Postgres.
	// The app has zero awareness of SPIFFE, Envoy, or mTLS.
	//
	// Both the username and password here are intentionally meaningless. The client-side
	// Envoy Wasm filter rewrites the username to the normalized SPIFFE ID path of the
	// workload ("client_proxy"), and replaces the password with a live JWT SVID fetched
	// from the SPIRE Agent. The app never knows either substitution happened.
	Host     = "envoy-client"
	Port     = 5432
	User     = "not-a-real-username"
	Password = "not-a-real-password"
	DBName   = "demo"
)

func main() {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		Host, Port, User, Password, DBName,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to open database connection: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	log.Printf("Connected to Postgres at %s:%d (username and password rewritten by Envoy Wasm filter)", Host, Port)

	// Create a test table if it doesn't exist.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS spiffe_demo (
		id   SERIAL PRIMARY KEY,
		msg  TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatalf("failed to create table: %v", err)
	}

	log.Printf("Created (or verified) table: spiffe_demo")

	// Insert a row.
	var id int
	err = db.QueryRow(
		`INSERT INTO spiffe_demo (msg) VALUES ($1) RETURNING id`,
		"Hello from SPIFFE-authenticated connection",
	).Scan(&id)
	if err != nil {
		log.Fatalf("failed to insert row: %v", err)
	}

	log.Printf("Inserted row with id=%d", id)

	// Read it back.
	var msg string
	err = db.QueryRow(`SELECT msg FROM spiffe_demo WHERE id = $1`, id).Scan(&msg)
	if err != nil {
		log.Fatalf("failed to retrieve row: %v", err)
	}

	log.Printf("Retrieved row: id=%d msg=%q", id, msg)

	log.Printf("Successfully queried Postgres through transparent Envoy mTLS sidecar proxy")
	os.Exit(0)
}
