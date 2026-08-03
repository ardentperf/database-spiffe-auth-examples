FROM ghcr.io/spiffe/spire-agent:1.14.0 AS spire

FROM postgres:16-bookworm

# Copy the spire-agent binary from the official SPIRE image.
# We only use its `api validate jwt` subcommand to validate JWT SVIDs from PAM.
COPY --from=spire /opt/spire/bin/spire-agent /usr/local/bin/spire-agent

# Install the JWT validation script and PAM service configuration.
# pam_exec.so is already present in postgres:16-bookworm (part of libpam-modules on Debian).
COPY verify-jwt.sh /opt/spiffe-auth/verify-jwt.sh
RUN chmod +x /opt/spiffe-auth/verify-jwt.sh
COPY postgres-spiffe.pam /etc/pam.d/postgres-spiffe

# Stage the custom pg_hba.conf. The init script copies it into $PGDATA after
# initdb creates the data directory (Docker's postgres image runs scripts in
# /docker-entrypoint-initdb.d/ after initdb completes).
COPY pg_hba.conf /etc/postgresql/pg_hba.conf
COPY 01-install-hba.sh /docker-entrypoint-initdb.d/01-install-hba.sh
RUN chmod +x /docker-entrypoint-initdb.d/01-install-hba.sh
