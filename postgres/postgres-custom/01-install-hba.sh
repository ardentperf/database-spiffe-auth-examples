#!/bin/bash
# Runs after initdb creates $PGDATA. Replaces the default pg_hba.conf with our
# custom one that uses PAM authentication for remote connections.
cp /etc/postgresql/pg_hba.conf "$PGDATA/pg_hba.conf"
