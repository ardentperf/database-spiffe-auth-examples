# SPIRE server

This is a simple configuration example for running a SPIRE server in the `demo.trust.geico` trust domain. The SPIRE
server bootstraps its own self-signed CA and uses in-memory SQLite. It does not persist the CA or the database file
to the file system, and thus should it restart all data will be lost.