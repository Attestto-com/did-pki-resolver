# @attestto/did-pki-resolver

Resolver for the [`did:pki`](https://github.com/Attestto-com/did-pki-spec) DID method — bridging national PKI hierarchies to the W3C DID ecosystem.

## What it does

Given a `did:pki` identifier, the resolver returns a W3C DID Document containing the Certificate Authority's public keys, trust chain position, and metadata.

```
did:pki:cr:sinpe:persona-fisica  →  DID Document (JWK keys, hierarchy, endEntityHints)
```

## Quick Start

```typescript
import { TrustRegistry, DidPkiResolver } from '@attestto/did-pki-resolver';

// Load trust store from @attestto/trust
const registry = new TrustRegistry('/path/to/attestto-trust/countries');
registry.load();

const resolver = new DidPkiResolver(registry);

// Resolve a DID
const result = resolver.resolve('did:pki:cr:sinpe:persona-fisica');
console.log(result.didDocument);
```

## Resolvable DIDs (Costa Rica)

```
did:pki:cr:raiz-nacional                → Root CA
did:pki:cr:politica:persona-fisica       → Policy CA (natural persons)
did:pki:cr:politica:persona-juridica     → Policy CA (legal entities)
did:pki:cr:sinpe:persona-fisica          → Issuing CA (natural persons)
did:pki:cr:sinpe:persona-juridica        → Issuing CA (legal entities)
```

## Architecture

```
┌────────────────┐     ┌──────────────┐     ┌──────────────────┐
│  DID String     │────▶│  Parser      │────▶│  Trust Registry  │
│  did:pki:cr:... │     │  (§4 ABNF)   │     │  (attestto-trust)│
└────────────────┘     └──────────────┘     └────────┬─────────┘
                                                      │
                        ┌──────────────┐     ┌────────▼─────────┐
                        │  DID Document │◀────│  Document Builder│
                        │  (W3C §5)    │     │  (X.509 → JWK)  │
                        └──────────────┘     └──────────────────┘
```

### Modules

| Module | Purpose |
|--------|---------|
| `parser.ts` | Parse/validate did:pki identifiers (spec §4) |
| `normalize.ts` | X.509 Subject DN → DID path segments (spec §7) |
| `registry.ts` | Trust registry — indexes attestto-trust manifests |
| `document.ts` | Build W3C DID Documents from cert data |
| `resolver.ts` | Main resolver — ties everything together |
| `countries.ts` | Country-specific metadata (hierarchy names, endEntityHints) |

## Data Source

The resolver reads from [`@attestto/trust`](https://github.com/Attestto-com/attestto-trust) — an independent public mirror of national PKI root and intermediate certificates. The trust store provides:

- PEM-encoded X.509 certificates
- `manifest.json` with parsed metadata (subject, issuer, fingerprints, validity)
- Hash-pinned, version-controlled audit trail

## Adding Countries

1. Add the country's CA certificates to `attestto-trust/countries/<cc>/current/`
2. Run `npm run generate` in attestto-trust to update manifests
3. Add a `CountryConfig` entry in `src/countries.ts` with hierarchy metadata and endEntityHints

## Tests

```bash
npm test
```

39 tests covering parser, normalization, and full resolution against real CR certificates.

## Specification

- [did:pki Method Specification](https://github.com/Attestto-com/did-pki-spec)
- [W3C DID Core v1.0](https://www.w3.org/TR/did-core/)
- W3C DID Extensions Registry: [PR #697](https://github.com/w3c/did-extensions/pull/697)

## License

Apache 2.0
