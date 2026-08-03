// pg-credential-injector is a proxy-wasm network filter that:
//
//  1. Rewrites the Postgres StartupMessage's username to the normalized SPIFFE
//     ID path. For example, the SPIFFE ID
//     "spiffe://demo.trust.geico/client-proxy" becomes the Postgres role name
//     "client_proxy" (hyphens → underscores, no domain prefix).
//  2. Intercepts the Postgres cleartext authentication exchange and injects a
//     JWT SVID as the password on behalf of the downstream client.
//  3. Fetches a JWT SVID from the SPIRE Agent Workload API before injecting the
//     credential.
//
// Wire protocol (cleartext / "password" auth):
//
//	Client → Server: StartupMessage     (user, database — no password field)
//	Server → Client: AuthenticationCleartextPassword  (type='R', auth_type=3)
//	Client → Server: PasswordMessage    (raw password string + null terminator)
//	Server → Client: AuthenticationOk   (type='R', auth_type=0)
//
// Injection strategy:
//
//  1. Receive client StartupMessage, rewrite the "user" field to the normalized
//     SPIFFE ID path (e.g. "client_proxy"), forward it. (INIT → WAIT_FOR_AUTH)
//  2. Forward AuthenticationCleartextPassword from server → client. (WAIT_FOR_AUTH → FETCHING_JWT)
//  3. When the client sends its PasswordMessage, pause it and dispatch a gRPC
//     call to the SPIRE Workload API to fetch a JWT SVID. (FETCHING_JWT → paused)
//  4. In the gRPC callback: replace the paused PasswordMessage buffer with the JWT
//     SVID as the password, and resume the TCP stream. (→ PASSTHROUGH)
//
// JWT fetch strategy:
//
//	The SPIRE Agent exposes a gRPC Workload API on a Unix socket. Envoy connects to
//	it via the "spire_agent" cluster (already configured for SDS). We reach it using
//	proxywasm.DispatchHttpCall with gRPC-over-HTTP/2 framing headers:
//
//	  content-type: application/grpc
//	  :path:        /SpiffeWorkloadAPI/FetchJWTSVID
//
//	The request body is a gRPC frame (5-byte header + protobuf-encoded JWTSVIDRequest).
//	The response body is a gRPC frame (5-byte header + protobuf-encoded JWTSVIDResponse).
//	Both protobuf messages are hand-encoded/decoded without the standard protobuf library
//	(which does not compile under TinyGo due to use of reflection).
package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

// ── State constants ──────────────────────────────────────────────────────────

const (
	stateInit        = iota // waiting for client StartupMessage
	stateWaitForAuth        // StartupMessage forwarded, waiting for server auth challenge
	stateFetchingJWT        // auth challenge forwarded, client PasswordMessage paused, fetching JWT
	statePassthrough        // auth done, forward everything unchanged
	stateDone               // terminal (error or unrecognised flow)
)

// ── Config ───────────────────────────────────────────────────────────────────

type config struct {
	SpiffeID string `json:"spiffe_id"`
}

// ── VMContext ────────────────────────────────────────────────────────────────

type vmContext struct{}

func (*vmContext) OnVMStart(_ int) types.OnVMStartStatus { return types.OnVMStartStatusOK }

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{contextID: contextID}
}

// ── PluginContext ────────────────────────────────────────────────────────────

type pluginContext struct {
	types.DefaultPluginContext
	contextID uint32
	cfg       config
	roleName  string // normalized SPIFFE ID path used as Postgres role name
}

func (p *pluginContext) OnPluginStart(_ int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogErrorf("pg-credential-injector: failed to read plugin config: %v", err)
		return types.OnPluginStartStatusFailed
	}
	if err := json.Unmarshal(data, &p.cfg); err != nil {
		proxywasm.LogErrorf("pg-credential-injector: failed to parse plugin config: %v", err)
		return types.OnPluginStartStatusFailed
	}
	p.roleName = normalizeSpiffeID(p.cfg.SpiffeID)
	proxywasm.LogInfof("pg-credential-injector: loaded config spiffe_id=%q role=%q", p.cfg.SpiffeID, p.roleName)
	return types.OnPluginStartStatusOK
}

func (p *pluginContext) NewTcpContext(contextID uint32) types.TcpContext {
	return &pgConn{
		contextID: contextID,
		spiffeID:  p.cfg.SpiffeID,
		roleName:  p.roleName,
		state:     stateInit,
	}
}

// ── TcpContext ───────────────────────────────────────────────────────────────

type pgConn struct {
	types.DefaultTcpContext
	contextID uint32
	spiffeID  string // full SPIFFE ID, used to request the specific JWT SVID from SPIRE
	roleName  string // pre-computed normalized SPIFFE ID path, used as the Postgres role name
	state     int
}

// OnDownstreamData handles client → server data.
func (c *pgConn) OnDownstreamData(dataSize int, _ bool) types.Action {
	switch c.state {
	case stateInit:
		if dataSize < 8 {
			return types.ActionPause
		}
		buf, err := proxywasm.GetDownstreamData(0, dataSize)
		if err != nil {
			proxywasm.LogErrorf("pg-credential-injector[%d]: GetDownstreamData error in stateInit: %v", c.contextID, err)
			c.state = stateDone
			return types.ActionContinue
		}
		// Rewrite the "user" field in the StartupMessage to the normalized role name.
		rewritten, ok := rewriteStartupUsername(buf, c.roleName)
		if !ok {
			proxywasm.LogWarnf("pg-credential-injector[%d]: could not rewrite StartupMessage username, forwarding as-is", c.contextID)
		} else if err := proxywasm.ReplaceDownstreamData(rewritten); err != nil {
			proxywasm.LogErrorf("pg-credential-injector[%d]: ReplaceDownstreamData (StartupMessage) error: %v", c.contextID, err)
		} else {
			proxywasm.LogInfof("pg-credential-injector[%d]: StartupMessage username rewritten to %q", c.contextID, c.roleName)
		}
		c.state = stateWaitForAuth
		return types.ActionContinue

	case stateFetchingJWT:
		// Client has sent its PasswordMessage while we are fetching the JWT.
		// Pause it; the gRPC callback will resume the stream after injecting the JWT.
		if dataSize < 1 {
			return types.ActionPause
		}
		buf, err := proxywasm.GetDownstreamData(0, dataSize)
		if err != nil {
			proxywasm.LogErrorf("pg-credential-injector[%d]: GetDownstreamData error: %v", c.contextID, err)
			c.state = stateDone
			return types.ActionContinue
		}
		if len(buf) > 0 && buf[0] == 'p' {
			// Dispatch the gRPC call to SPIRE, then pause the stream until we get the JWT.
			if err := c.dispatchJWTFetch(); err != nil {
				proxywasm.LogErrorf("pg-credential-injector[%d]: dispatchJWTFetch error: %v", c.contextID, err)
				c.state = stateDone
				return types.ActionContinue
			}
			// Paused; the callback will inject the JWT and resume.
			return types.ActionPause
		}
		proxywasm.LogWarnf("pg-credential-injector[%d]: expected PasswordMessage in FETCHING_JWT but got type=%q", c.contextID, string(buf[0]))
		c.state = stateDone
		return types.ActionContinue

	default:
		return types.ActionContinue
	}
}

// OnUpstreamData handles server → client data.
func (c *pgConn) OnUpstreamData(dataSize int, _ bool) types.Action {
	switch c.state {
	case stateWaitForAuth:
		if dataSize < 9 {
			return types.ActionPause
		}
		buf, err := proxywasm.GetUpstreamData(0, dataSize)
		if err != nil {
			proxywasm.LogErrorf("pg-credential-injector[%d]: GetUpstreamData error: %v", c.contextID, err)
			c.state = stateDone
			return types.ActionContinue
		}
		msgType := buf[0]
		authType := int32(binary.BigEndian.Uint32(buf[5:9]))

		if msgType == 'R' && authType == 3 {
			proxywasm.LogInfof("pg-credential-injector[%d]: AuthenticationCleartextPassword, forwarding to client", c.contextID)
			c.state = stateFetchingJWT
			return types.ActionContinue
		}
		if msgType == 'R' && authType == 0 {
			proxywasm.LogInfof("pg-credential-injector[%d]: AuthenticationOk (no challenge), PASSTHROUGH", c.contextID)
			c.state = statePassthrough
			return types.ActionContinue
		}
		if msgType == 'E' {
			proxywasm.LogErrorf("pg-credential-injector[%d]: ErrorResponse in WAIT_FOR_AUTH", c.contextID)
			c.state = stateDone
			return types.ActionContinue
		}
		proxywasm.LogWarnf("pg-credential-injector[%d]: unexpected msg type=%q authType=%d in WAIT_FOR_AUTH", c.contextID, string(msgType), authType)
		c.state = stateDone
		return types.ActionContinue

	default:
		return types.ActionContinue
	}
}

// ── JWT fetch via gRPC-over-HTTP/2 (DispatchHttpCall) ────────────────────────

// dispatchJWTFetch sends FetchJWTSVID to the SPIRE Workload API using DispatchHttpCall
// with gRPC framing. The spire_agent cluster uses HTTP/2 (http2_protocol_options: {}).
func (c *pgConn) dispatchJWTFetch() error {
	pbBody := encodeJWTSVIDRequest("postgres", c.spiffeID)
	grpcFrame := makeGRPCFrame(pbBody)

	headers := [][2]string{
		{":method", "POST"},
		{":authority", "spire-agent"},
		{":path", "/SpiffeWorkloadAPI/FetchJWTSVID"},
		{"content-type", "application/grpc"},
		// The SPIFFE Workload Endpoint spec requires this header as an SSRF hardening
		// measure. All requests to the Workload API must include it.
		{"workload.spiffe.io", "true"},
	}

	conn := c
	contextID := c.contextID

	_, err := proxywasm.DispatchHttpCall(
		"spire_agent",
		headers,
		grpcFrame,
		nil,
		5000,
		func(numHeaders, bodySize, numTrailers int) {
			readSize := bodySize
			if readSize == 0 {
				readSize = 65536
			}
			body, err := proxywasm.GetHttpCallResponseBody(0, readSize)
			if err != nil || len(body) <= 5 {
				proxywasm.LogErrorf("pg-credential-injector[%d]: failed to read JWT SVID response: %v", contextID, err)
				conn.state = stateDone
				return
			}
			jwt := decodeJWTSVIDResponse(body[5:])
			if jwt == "" {
				proxywasm.LogErrorf("pg-credential-injector[%d]: JWT SVID response was empty", contextID)
				conn.state = stateDone
				return
			}
			proxywasm.LogInfof("pg-credential-injector[%d]: fetched JWT SVID from SPIRE (len=%d)", contextID, len(jwt))

			// Inject the JWT SVID as the Postgres password.
			// Postgres validates it server-side via PAM + spire-agent api validate jwt.
			pwMsg := buildPasswordMessage(jwt)
			if err := proxywasm.ReplaceDownstreamData(pwMsg); err != nil {
				proxywasm.LogErrorf("pg-credential-injector[%d]: ReplaceDownstreamData error: %v", contextID, err)
			} else {
				proxywasm.LogInfof("pg-credential-injector[%d]: replaced client PasswordMessage with JWT SVID", contextID)
			}
			conn.state = statePassthrough
			if err := proxywasm.SetEffectiveContext(contextID); err != nil {
				proxywasm.LogErrorf("pg-credential-injector[%d]: SetEffectiveContext error: %v", contextID, err)
			}
			if err := proxywasm.ContinueTcpStream(); err != nil {
				proxywasm.LogErrorf("pg-credential-injector[%d]: ContinueTcpStream error: %v", contextID, err)
			}
		},
	)
	return err
}

// ── SPIFFE ID normalization ───────────────────────────────────────────────────

// normalizeSpiffeID converts a SPIFFE ID to a valid, unquoted Postgres role name.
// Strips "spiffe://<trust-domain>/" and replaces hyphens, slashes, and dots with underscores.
//
//	spiffe://demo.trust.geico/client-proxy → client_proxy
//	spiffe://demo.trust.geico/services/db  → services_db
func normalizeSpiffeID(spiffeID string) string {
	s := strings.TrimPrefix(spiffeID, "spiffe://")
	if slash := strings.Index(s, "/"); slash >= 0 {
		s = s[slash+1:]
	}
	out := make([]byte, len(s))
	for i := range s {
		if s[i] == '-' || s[i] == '/' || s[i] == '.' {
			out[i] = '_'
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}

// ── Postgres StartupMessage rewriting ────────────────────────────────────────

// rewriteStartupUsername parses a Postgres StartupMessage and replaces the
// value of the "user" key with newUsername. It recalculates the 4-byte message
// length prefix and returns the new buffer. Returns (nil, false) if the message
// is not a valid StartupMessage or does not contain a "user" key.
//
// StartupMessage wire format:
//
//	int32  total length (includes the 4-byte length field itself)
//	int32  protocol version (196608 = 3.0)
//	bytes  NUL-terminated key-value pairs: "key\0value\0..." followed by a final \0
func rewriteStartupUsername(buf []byte, newUsername string) ([]byte, bool) {
	if len(buf) < 8 {
		return nil, false
	}
	// Verify protocol version 3.0 (0x00030000 = 196608).
	proto := binary.BigEndian.Uint32(buf[4:8])
	if proto != 196608 {
		return nil, false
	}

	// Parse NUL-terminated key-value pairs starting at offset 8.
	kvStart := 8
	kvEnd := len(buf)
	// The last byte should be a terminating NUL.
	if kvEnd > kvStart && buf[kvEnd-1] == 0 {
		kvEnd--
	}

	// Collect all key-value pairs, replacing the "user" value.
	type kv struct{ key, val string }
	var pairs []kv
	i := kvStart
	for i < kvEnd {
		// Read key.
		keyStart := i
		for i < kvEnd && buf[i] != 0 {
			i++
		}
		if i >= kvEnd {
			break
		}
		key := string(buf[keyStart:i])
		i++ // consume NUL

		// Read value.
		valStart := i
		for i < kvEnd && buf[i] != 0 {
			i++
		}
		val := string(buf[valStart:i])
		if i < kvEnd {
			i++ // consume NUL
		}

		if key == "user" {
			val = newUsername
		}
		pairs = append(pairs, kv{key, val})
	}

	if len(pairs) == 0 {
		return nil, false
	}

	// Re-encode: 4-byte length + 4-byte protocol + key\0value\0... + \0
	body := make([]byte, 0, 64)
	for _, p := range pairs {
		body = append(body, []byte(p.key)...)
		body = append(body, 0)
		body = append(body, []byte(p.val)...)
		body = append(body, 0)
	}
	body = append(body, 0) // final terminating NUL

	totalLen := 4 + 4 + len(body) // length field + protocol + kv pairs
	out := make([]byte, 4+4+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(out[4:8], proto)
	copy(out[8:], body)
	return out, true
}

// ── Protobuf wire format helpers ─────────────────────────────────────────────

// encodeJWTSVIDRequest encodes JWTSVIDRequest{audience: [audience], spiffe_id: spiffeID} manually.
//
// Protobuf wire format:
//
//	field 1 (repeated string audience): tag=0x0A, varint length, UTF-8 bytes
//	field 2 (string spiffe_id):         tag=0x12, varint length, UTF-8 bytes
//
// Requesting a specific spiffe_id ensures SPIRE returns the correct SVID when
// multiple SVIDs are registered for the same workload (e.g. both Envoy sidecars
// share the same Docker image and thus the same SPIRE selector).
func encodeJWTSVIDRequest(audience, spiffeID string) []byte {
	ab := []byte(audience)
	sb := []byte(spiffeID)
	buf := make([]byte, 0, 2+len(ab)+2+len(sb))
	buf = append(buf, 0x0A)          // field 1, wire type 2
	buf = append(buf, byte(len(ab))) // varint length
	buf = append(buf, ab...)
	buf = append(buf, 0x12)          // field 2, wire type 2
	buf = append(buf, byte(len(sb))) // varint length
	buf = append(buf, sb...)
	return buf
}

// makeGRPCFrame wraps a protobuf message body in the 5-byte gRPC frame header.
//
//	[compressed_flag (1 byte)] [message_length (4 bytes, big-endian)] [body]
func makeGRPCFrame(body []byte) []byte {
	frame := make([]byte, 5+len(body))
	frame[0] = 0x00 // not compressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	return frame
}

// decodeJWTSVIDResponse extracts the JWT string from a JWTSVIDResponse protobuf message.
//
// JWTSVIDResponse { repeated JWTSVID svids = 1; }
// JWTSVID         { string spiffe_id = 1; string svid = 2; }
func decodeJWTSVIDResponse(buf []byte) string {
	// Field 1 of the outer message is the first JWTSVID submessage (length-delimited).
	// Field 2 of that submessage is the svid string.
	if svid := pbField(buf, 1); svid != nil {
		return string(pbField(svid, 2))
	}
	return ""
}

// pbField walks a protobuf-encoded message and returns the raw bytes of the first
// occurrence of fieldNum (wire type 2 / length-delimited). Returns nil if not found.
func pbField(buf []byte, fieldNum uint64) []byte {
	i := 0
	for i < len(buf) {
		tag, n := decodeVarint(buf[i:])
		if n == 0 {
			break
		}
		i += n
		fn, wt := tag>>3, tag&0x07
		switch wt {
		case 2:
			length, n2 := decodeVarint(buf[i:])
			if n2 == 0 {
				return nil
			}
			i += n2
			if i+int(length) > len(buf) {
				return nil
			}
			data := buf[i : i+int(length)]
			i += int(length)
			if fn == fieldNum {
				return data
			}
		case 0:
			_, n2 := decodeVarint(buf[i:])
			if n2 == 0 {
				return nil
			}
			i += n2
		case 1:
			i += 8
		case 5:
			i += 4
		default:
			return nil
		}
	}
	return nil
}

// decodeVarint decodes a protobuf varint from buf and returns the value and bytes consumed.
// Returns (0, 0) on error.
func decodeVarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if i == 10 {
			return 0, 0 // overflow
		}
		if b < 0x80 {
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

// ── Postgres wire format helpers ─────────────────────────────────────────────

// buildPasswordMessage constructs a Postgres PasswordMessage ('p'):
//
//	byte:  'p'
//	int32: msgLen = 4 + len(password) + 1  (includes the length field itself)
//	bytes: password + null terminator
func buildPasswordMessage(password string) []byte {
	pwBytes := []byte(password)
	msgLen := 4 + len(pwBytes) + 1
	buf := make([]byte, 1+msgLen)
	buf[0] = 'p'
	binary.BigEndian.PutUint32(buf[1:5], uint32(msgLen))
	copy(buf[5:], pwBytes)
	buf[5+len(pwBytes)] = 0x00
	return buf
}
