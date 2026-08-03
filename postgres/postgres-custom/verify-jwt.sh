#!/bin/sh
# Called by pam_exec with expose_authtok: reads the JWT SVID from stdin,
# validates it against the local SPIRE Agent's trust bundle (Unix socket, no
# network call), and exits 0 (PAM_SUCCESS) or non-zero (PAM_AUTH_ERR).
#
# Two checks are performed:
#   1. Cryptographic validity + audience (spire-agent api validate jwt)
#   2. The JWT subject matches the connecting Postgres username. The subject
#      is a SPIFFE ID (e.g. "spiffe://demo.trust.geico/client-proxy") and the
#      username is its normalized path (e.g. "client_proxy"). We derive the
#      expected username from the subject using the same normalization rule as
#      the Wasm filter: strip "spiffe://<domain>/", replace "-", "/", "." → "_".
#
# The spire-agent-socket volume is mounted at /tmp/spire-agent in the postgres
# container. The socket lives at /tmp/spire-agent/api.sock.
read -r JWT

# Validate JWT cryptographically and capture output to extract the subject.
VALIDATION_OUTPUT=$(/usr/local/bin/spire-agent api validate jwt \
    -audience postgres \
    -svid "$JWT" \
    -socketPath /tmp/spire-agent/api.sock \
    2>&1)

if [ $? -ne 0 ]; then
    exit 1
fi

# Extract the SPIFFE ID from the "SPIFFE ID : ..." line in the output.
SPIFFE_ID=$(echo "$VALIDATION_OUTPUT" | grep "^SPIFFE ID" | awk '{print $NF}')

# Strip "spiffe://<trust-domain>/" prefix to get the path component.
PATH_COMPONENT=$(echo "$SPIFFE_ID" | sed 's|spiffe://[^/]*/||')

# Normalize: replace hyphens, slashes, and dots with underscores.
# Uses sed with explicit alternation to avoid tr range interpretation issues.
EXPECTED_USER=$(echo "$PATH_COMPONENT" | sed 's/[-/.]/_/g')

# Reject if the JWT subject doesn't match the connecting username.
if [ "$EXPECTED_USER" != "$PAM_USER" ]; then
    exit 1
fi

exit 0
