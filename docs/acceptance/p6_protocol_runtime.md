# P6 Protocol Runtime Acceptance

## Closed bounded scope

The `p6-protocol-runtime-loopback` fixture executes the production
`ProtocolRuntimeProvider` against a real local TLS echo server. It captures
application bytes through a provider-managed TLS endpoint, materializes the
capture artifact, replays the ordered TCP session over a second verified TLS
connection, checks the source certificate binding, and closes all sockets.

The retained contract requires:

- production provider provenance and real socket evidence;
- verified TLS 1.2 or later with no private key or session key persisted;
- a matching replay certificate pin before application bytes are sent;
- preserved source frame order and exact echo verification;
- capture and replay audit artifacts with SHA-256 entries;
- target identity, execution proof, and rollback/cleanup evidence.

The fixture is non-mutating with respect to the captured target, but its
registered contract still requires the provider rollback/socket-close artifact
as cleanup proof. The verifier rechecks that artifact independently from the
record's persisted boolean constraints.

The production HTTP/1.1 capture path also recognizes a bounded loopback
`CONNECT` session. After a successful `2xx` response it switches to opaque
tunnel mode and retains the authority, handshake status, bidirectional tunnel
byte counts and SHA-256 values, while preserving ordered transcript frame
evidence, source-frame references, TCP half-close propagation/peer-EOF evidence,
and verified socket cleanup. The bounded replay path replays only IPv4/IPv6
loopback authorities and validates the retained endpoint identity before any
bytes are sent. The tunneled protocol is intentionally not decoded or replayed
as HTTP.

For ordinary HTTP/1.1 transactions, the capture and replay path preserves a
bounded sequence of informational responses before the final response. Replay
requires the controlled fixture to return the same number of responses in the
same order, with exact wire-byte matches for every retained `1xx` response and
the final response. Status `101` remains outside this path because it changes
the protocol rather than continuing the HTTP/1.1 response sequence.

The `protocol_adapter_preflight` action provides a local, non-transmitting
HTTP/2 adapter readiness check. Its versioned contract probes the `hyper-h2`
implementation (`h2>=4.1,<5`), records dependency identity and required frame,
HPACK, connection-state, and multiplexing capabilities, and emits an auditable
artifact. The repository does not currently declare that dependency, and the
preflight explicitly records `capture_supported: false`,
`replay_supported: false`, and `live_verified: false`; it is not HTTP/2 runtime
or acceptance evidence.

Run the opt-in fixture through the acceptance registry:

```powershell
python -m reverse_analyzer environment accept run `
  --fixture p6-protocol-runtime-loopback `
  --workspace <workspace> `
  --execute `
  --timeout 60
```

The runner injects `RUN_PROTOCOL_RUNTIME_LIVE=1`; direct test execution remains
skipped unless that variable is explicitly set. A successful run records
`live_verified: true` only after command success, artifact completeness,
non-synthetic provenance, target identity, and execution proof validation.

## Remaining boundary

This acceptance covers controlled IPv4 loopback TLS capture and ordered session
replay. Bounded loopback opaque CONNECT capture and replay, including transcript
and half-close verification, and exact informational-response sequence replay
are complete for the declared scope. Generalized CONNECT replay,
arbitrary-interface capture, unmanaged TLS
decryption, HTTP/2 and HTTP/3, and unrestricted remote endpoint/session replay
remain outside the accepted scope. Passive adapter execution also remains
dependent on an installed local capture tool and is limited to a loopback
interface.
