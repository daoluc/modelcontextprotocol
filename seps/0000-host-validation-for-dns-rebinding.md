# SEP-0000: Host Validation for DNS Rebinding Protection in Streamable HTTP

- **Status**: Draft
- **Type**: Standards Track
- **Created**: 2026-09-23
- **Author(s)**: Luc Dao (@daoluc)
- **Sponsor**: Paul Carleton
- **PR**: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/{NUMBER}

## Abstract

The Streamable HTTP transport requires servers to validate the `Origin` header
"to prevent DNS rebinding attacks". The header that identifies a rebinding
attack is `Host`, not `Origin`. This SEP changes that requirement to validate
`Host` instead.

## Motivation

Discussion and the full threat model are in
[#3370](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3370).

**`Origin` is the wrong control for DNS rebinding.** In a rebinding attack, a
page on `evil.example` re-resolves to a loopback or private address. Every
request it sends carries `Host: evil.example`, but `Origin` is omitted on the
same-origin `GET` that opens the SSE stream. The SDK advisories that motivated
this requirement
([GHSA-w48q-cv73-mx4w](https://github.com/advisories/GHSA-w48q-cv73-mx4w),
[GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f)) were
fixed by validating `Host`.

**Requiring `Origin` blocks legitimate clients.** A browser-extension MCP
client holding a valid bearer token gets 200 for a request with no `Origin`
header, and 403 for the same request when the browser attaches
`Origin: chrome-extension://<id>`. Operators can only fix this by allowlisting
each client by hand. For Firefox that isn't possible, because
`moz-extension://` origins differ on every install.

**Implementations have already moved.** The conformance scenario
`dns-rebinding-protection` accepts "Host **or** Origin" validation. The Go SDK
validates `Host` on loopback by default and made `Origin` protection opt-in in
v1.6.0.

## Specification

In "Security & Endpoint" of `basic/transports/streamable-http`, replace item 1
with:

1. Servers **MUST** validate the `Host` header on all incoming connections to
   prevent DNS rebinding attacks.
   - If the `Host` header is invalid, servers **MUST** respond with HTTP 403
     Forbidden. The HTTP response body **MAY** comprise a JSON-RPC _error
     response_ that has no `id`.

The remaining items are unchanged.

## Rationale

`Host` is present on every HTTP/1.1 request, and in a rebinding attack it
always names the attacker's domain. `Origin` validation is a defense against
cross-site request forgery, which is a general HTTP concern rather than one
specific to MCP, as the Go SDK's `docs/rough_edges.md` notes about its
`CrossOriginProtection` option. The spec therefore does not replace the
`Origin` requirement with another.

**Alternative considered:** keeping the `Origin` requirement and adding scheme
wildcards (`chrome-extension://*`) to SDK allowlists. That helps Chrome but not
Firefox, and still ties rebinding protection to a header that is absent on SSE
`GET`s.

## Backward Compatibility

- **Clients:** no change.
- **Servers:** a server that validates only `Origin` would need to add `Host`
  validation. The TypeScript, Python and Go SDKs already validate `Host` by
  default on localhost binds, and the conformance scenario already accepts
  `Host` validation.

## Security Implications

- DNS rebinding protection is unchanged or stronger: `Host` is also checked on
  the SSE `GET`, where `Origin` is absent.
- Removing the `Origin` requirement removes an incidental CSRF defense for
  servers that accept ambient credentials such as cookies. Such servers should
  apply standard CSRF defenses, for example `Origin` checks or `SameSite`
  cookies, as they would for any HTTP API.
- An unauthenticated local server without an `Origin` check is protected from
  cross-site requests only while it sends no permissive CORS headers and
  rejects non-JSON POST bodies. A JSON body forces a CORS preflight, which a
  server without CORS headers fails, and a non-JSON body is rejected before it
  reaches a tool. The official SDKs do both by default on the MCP endpoint, but
  the specification requires neither. See Open Question 2.

## Reference Implementation

- **Go SDK** (v1.6.0+): `Host` validation on loopback by default, `Origin`
  opt-in (`mcp/streamable.go`).
- **TypeScript and Python SDKs:** prototype branches that make `Origin`
  validation opt-in while keeping `Host` validation on by default will be
  linked here.
- **Conformance:** the existing `dns-rebinding-protection` scenario already
  covers item 1.

## Open Questions

1. The Python SDK rejects an invalid `Host` with 421 Misdirected Request rather
   than 403. Should item 1 allow any 4xx, as the conformance scenario does?
2. **CORS on unauthenticated local servers.** Today the `Origin` check also
   neutralizes permissive CORS. The TypeScript SDK's examples add
   `cors({ origin: '*' })` to the MCP endpoint and stay safe only because
   `createMcpExpressApp()` rejects non-localhost origins on loopback binds.
   Without the `Origin` requirement, an unauthenticated local server that sends
   `Access-Control-Allow-Origin: *` can be driven by any website, and `Host`
   validation does not help because the request genuinely targets `localhost`.
   The specification does not currently require closed CORS or rejection of
   non-JSON POST bodies. Should this SEP add, for servers that do not
   authenticate every request, one or more of:
   - servers **MUST NOT** send `Access-Control-Allow-Origin: *` or reflect
     arbitrary origins;
   - servers **MUST** reject POST bodies whose media type is not
     `application/json`;
   - servers that send CORS headers **MUST** also validate `Origin`?

## Acknowledgments

@kurtisvg and @pcarleton for the transports-WG discussion that led to #3370.
