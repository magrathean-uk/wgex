# UAPI fixture goldens

All key bytes come from `Tests/Fixtures/keys`; they are throwaway fixtures.
These documents must never be used for an operational tunnel.

The three full documents correspond to the same-named `.conf` fixtures. They
were generated independently with Python's base64 decoder and direct field
assembly, rather than by recording the Swift encoder's output. The multi-peer
hostname has an explicit offline underlay-resolution override of
`192.0.2.1:51820`. No DNS query is performed by the tests or encoder.

`endpoint-update.uapi` updates the server fixture public key to
`[2001:db8::2]:51821`. Documents use LF endings and a final LF; no UAPI socket
command header is included because the C ABI takes the configuration payload.
