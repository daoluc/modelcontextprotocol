# SEP-0000: Host Validation for DNS Rebinding Protection in Streamable HTTP

- **Status**: Draft
- **Type**: Standards Track
- **Created**: 2026-09-23
- **Author(s)**: Luc Dao <daonguyenluc@gmail.com> (@daoluc)
- **Sponsor**: None (seeking sponsor)
- **PR**: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/{NUMBER}

## Abstract

The Streamable HTTP transport currently requires servers to validate the
`Origin` header "to prevent DNS rebinding attacks", and to reject an invalid
`Origin` with 403. `Origin` is the wrong control for that threat. It is absent
on the same-origin `GET` that opens an SSE stream, and a present `Origin` is
also sent by legitimate browser-hosted clients such as extensions
(`chrome-extension://<id>`, `moz-extension://<uuid>`). This SEP restates the
requirement in terms of the threat. Servers **MUST** protect against DNS
rebinding by validating `Host` against the names they serve, on every listener.
Validating `Origin` instead remains conformant. `Origin` checks are
**RECOMMENDED** where the server accepts ambient credentials, and a server that
requires a non-ambient credential on every request **MAY** accept any `Origin`.

## Motivation

Discussion and the full threat model are in
[#3370](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3370).

**Interoperability.** A browser-extension MCP client that has completed OAuth
against a remote server gets 200 for a request with no `Origin` header, and 403
for the same request with the same bearer token when the browser attaches
`Origin: chrome-extension://<id>`. Operators can only fix this by allowlisting
each client by hand. For Firefox that isn't possible, because
`moz-extension://` origins differ on every install.

**The requirement does not match the threat it cites.** In DNS rebinding, a
page on `evil.example` re-resolves to a loopback or private address and sends
requests the browser treats as same-origin. The request always carries
`Host: evil.example`, while `Origin` is omitted on the `GET` that opens the SSE
stream. The SDK advisories that motivated this requirement
([GHSA-w48q-cv73-mx4w](https://github.com/advisories/GHSA-w48q-cv73-mx4w),
[GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f)) were
fixed by validating `Host`.

**The spec is already stricter than implementations and conformance.** The
conformance scenario `dns-rebinding-protection` states "Server MUST validate the
Host **or** Origin header" and accepts any 4xx. The Go SDK validates `Host` on
loopback by default and made `Origin` protection opt-in in v1.6.0, after one
release with it on by default. Its `docs/rough_edges.md` notes that
cross-origin protection "is a general HTTP concern, not specific to MCP".

`Origin` validation is still the right defense against cross-site request
forgery when a server accepts credentials the browser attaches automatically.
This SEP keeps it for that case.

## Specification

Replace items 1–3 of "Security & Endpoint" in
`basic/transports/streamable-http` with:

1. Servers **MUST** protect against DNS rebinding attacks by validating the
   `Host` header of every incoming request, on every listener, against the host
   names the server is intended to serve. Validating the `Origin` header
   instead, as required by earlier revisions of this specification, also
   satisfies this requirement.
   - If the `Host` header is not one the server serves, servers **MUST** reject
     the request with an HTTP 4xx status; 403 Forbidden is **RECOMMENDED**.
2. Servers that accept ambient credentials (credentials a browser attaches
   automatically, such as cookies, cached HTTP authentication, or TLS client
   certificates) **SHOULD** also validate the `Origin` header to prevent
   cross-site request forgery.
   - If a server validates the `Origin` header and it is present and invalid,
     the server **MUST** respond with HTTP 403 Forbidden. The HTTP response body
     **MAY** comprise a JSON-RPC _error response_ that has no `id`.
3. A server that requires a non-ambient credential, such as a bearer token in
   the `Authorization` header, on every request and on every listener **MAY**
   accept requests with any `Origin` value. Such a server still **MUST**
   validate the `Host` header as described in (1).
4. When running locally, servers **SHOULD** bind only to localhost (127.0.0.1)
   rather than all network interfaces (0.0.0.0).
5. Servers **SHOULD** implement proper authentication for all connections.

Items 4 and 5 are unchanged from the current text (previously 2 and 3).

## Rationale

- **`Host` rather than `Origin` for rebinding.** `Host` is present on every
  HTTP/1.1 request, and in a rebinding attack it always names the attacker's
  domain. `Origin` is missing on same-origin `GET`s and is legitimately
  arbitrary for non-web browser contexts.
- **"On every listener".** Rebinding applies to any server that grants
  authority by network position: loopback, LAN/VPN/VPC hosts, and source-IP
  allowlists. It also applies to plain-HTTP backends behind a TLS front door.
  Validating `Host` against the names the server serves covers all of these;
  HTTPS alone does not.
- **Keeping `Origin` validation conformant.** Existing servers that validate
  `Origin` do not become non-conformant. This mirrors the conformance
  scenario's "Host or Origin".
- **The non-ambient-credential clause.** An attacking page cannot attach a
  bearer token the browser does not hold on its behalf, so an `Origin`
  allowlist adds nothing against that attacker. It does, however, block
  legitimate browser-hosted clients.

**Alternatives considered:**

- **Keep the MUST and add scheme wildcards for `Origin` in SDKs.** This eases
  Chrome but not Firefox, and it still ties rebinding protection to a header
  that is absent on SSE `GET`s.
- **Exempt only remote HTTPS servers.** This misses private-network and
  source-IP-trusting deployments, which are rebindable.

## Backward Compatibility

- **Servers:** every server conformant today, which validates `Origin`, remains
  conformant. Servers that validate only `Host` become conformant; they already
  pass the conformance scenario.
- **Clients:** no change.
- **Rejection status:** a server that rejects an invalid `Host` with a status
  other than 403 (for example, the Python SDK returns 421) is conformant under
  "4xx".

## Security Implications

- DNS rebinding protection is unchanged or stronger. `Host` is checked on the
  SSE `GET` too, and the requirement now covers non-loopback listeners
  explicitly.
- A server that drops `Origin` validation because it requires bearer tokens
  loses CSRF protection only if it also accepts ambient credentials. Item 3
  requires the non-ambient credential on _every_ request and listener to rule
  this out.
- Unauthenticated local servers remain exposed to cross-site simple requests
  if they do not enforce `Content-Type: application/json` on POST. The
  transport requires JSON bodies, and the official SDKs reject other content
  types, which forces a CORS preflight. See Open Questions.

## Reference Implementation

- **Go SDK** (v1.6.0+): `Host` validation on loopback by default
  (`DisableLocalhostProtection`), `Origin` opt-in (`mcp/streamable.go`).
- **TypeScript and Python SDKs:** matching changes proposed in LINK-TS-ISSUE
  and LINK-PY-ISSUE; prototype branches TBD.
- **Conformance:** the existing `dns-rebinding-protection` scenario already
  matches item 1. A new scenario could check that a request with a valid
  `Host`, a valid bearer token and `Origin: chrome-extension://x` is not
  rejected with 403 by servers that opt into item 3. This would be informative
  only, since item 3 is a MAY.

## Open Questions

1. Should the rejection status for an invalid `Host` be exactly 403, for
   consistency with the `Origin` rule, or any 4xx, which matches conformance
   and allows the Python SDK's 421?
2. Should servers that grant authority by network position, such as
   unauthenticated local servers, count as accepting "ambient credentials" for
   item 2, making `Origin` validation RECOMMENDED for them too?
3. Should the spec require servers to reject POST bodies whose `Content-Type`
   is not `application/json`, so the preflight argument does not depend on SDK
   behaviour?
4. Should `security_best_practices` gain a short section distinguishing the
   rebinding threat from the CSRF threat?

## Acknowledgments

@kurtisvg and @pcarleton for the transports-WG discussion that led to #3370.
