import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { TrustRegistry } from '../src/registry.js';
import { DidPkiResolver } from '../src/resolver.js';

const TRUST_STORE = join(import.meta.dirname, '..', '..', 'attestto-trust', 'countries');

describe('DidPkiResolver', () => {
  let resolver: DidPkiResolver;

  before(() => {
    const registry = new TrustRegistry(TRUST_STORE);
    registry.load();
    resolver = new DidPkiResolver(registry);
  });

  it('resolves CR root CA', () => {
    const result = resolver.resolve('did:pki:cr:raiz-nacional');
    assert.equal(result.didResolutionMetadata.error, undefined);
    assert.notEqual(result.didDocument, null);
    assert.equal(result.didDocument!.id, 'did:pki:cr:raiz-nacional');
    assert.equal(result.didDocument!.controller, 'did:pki:cr:raiz-nacional');
    assert.equal(result.didDocument!.pkiMetadata.level, 'root');
    assert.equal(result.didDocument!.pkiMetadata.country, 'CR');
    assert.equal(result.didDocument!.pkiMetadata.countryName, 'Costa Rica');
    assert.ok(result.didDocument!.verificationMethod.length >= 1);
    assert.ok(result.didDocument!.assertionMethod.length >= 1);
  });

  it('resolves CR policy CA', () => {
    const result = resolver.resolve('did:pki:cr:politica:persona-fisica');
    assert.equal(result.didResolutionMetadata.error, undefined);
    assert.notEqual(result.didDocument, null);
    assert.equal(result.didDocument!.id, 'did:pki:cr:politica:persona-fisica');
    assert.equal(result.didDocument!.pkiMetadata.level, 'policy');
    assert.equal(result.didDocument!.controller, 'did:pki:cr:raiz-nacional');
  });

  it('resolves CR issuing CA with multiple generations', () => {
    const result = resolver.resolve('did:pki:cr:sinpe:persona-fisica');
    assert.equal(result.didResolutionMetadata.error, undefined);
    assert.notEqual(result.didDocument, null);
    assert.equal(result.didDocument!.id, 'did:pki:cr:sinpe:persona-fisica');
    assert.equal(result.didDocument!.pkiMetadata.level, 'issuing');
    // Should have 2 generations (2019 + 2023)
    assert.ok(result.didDocument!.pkiMetadata.generations.length >= 2,
      `Expected 2+ generations, got ${result.didDocument!.pkiMetadata.generations.length}`);
    assert.ok(result.didDocument!.verificationMethod.length >= 2);
    // Should have endEntityHints
    assert.ok(result.didDocument!.pkiMetadata.endEntityHints);
    assert.equal(result.didDocument!.pkiMetadata.endEntityHints!.nationalIdFormat, 'CR-cedula');
  });

  it('resolves CR issuing CA persona juridica', () => {
    const result = resolver.resolve('did:pki:cr:sinpe:persona-juridica');
    assert.equal(result.didResolutionMetadata.error, undefined);
    assert.notEqual(result.didDocument, null);
    assert.equal(result.didDocument!.pkiMetadata.level, 'issuing');
  });

  it('returns DID Document metadata', () => {
    const result = resolver.resolve('did:pki:cr:raiz-nacional');
    assert.ok(result.didDocumentMetadata.created);
    assert.ok(result.didDocumentMetadata.updated);
    assert.ok(result.didDocumentMetadata.versionId);
    assert.equal(result.didDocumentMetadata.deactivated, undefined);
  });

  it('emits x5t#S256 as base64url matching the generation fingerprint (RFC 7517)', () => {
    const result = resolver.resolve('did:pki:cr:raiz-nacional');
    const doc = result.didDocument!;
    const generations = doc.pkiMetadata.generations;

    for (const vm of doc.verificationMethod) {
      assert.equal(vm.type, 'JsonWebKey2020');
      assert.ok(vm.publicKeyJwk.kty, 'JWK must have kty');

      // Must use x5t#S256 (SHA-256), never bare x5t (RFC 7517 = SHA-1).
      assert.equal((vm.publicKeyJwk as Record<string, unknown>).x5t, undefined, 'must not emit bare x5t');
      const thumb = vm.publicKeyJwk['x5t#S256'];
      assert.ok(thumb, 'must emit x5t#S256');

      // Must be unpadded base64url decoding to a 32-byte SHA-256 digest.
      assert.match(thumb!, /^[A-Za-z0-9_-]+$/, 'x5t#S256 must be unpadded base64url');
      const bytes = Buffer.from(thumb!, 'base64url');
      assert.equal(bytes.length, 32, 'x5t#S256 must decode to 32 bytes (SHA-256)');

      // Must agree with the matching generation's hex fingerprint.
      const fragment = vm.id.split('#')[1];
      const gen = generations.find((g) => g.keyId.replace(/^#/, '') === fragment);
      assert.ok(gen, `no generation for keyId #${fragment}`);
      assert.equal(gen!.fingerprintAlgorithm, 'sha-256');
      assert.equal(bytes.toString('hex'), gen!.fingerprint, 'x5t#S256 must decode to the generation fingerprint');
    }
  });

  it('returns error for invalid DID', () => {
    const result = resolver.resolve('did:web:example.com');
    assert.equal(result.didDocument, null);
    assert.equal(result.didResolutionMetadata.error, 'invalidDid');
  });

  it('returns error for unknown CA', () => {
    const result = resolver.resolve('did:pki:cr:nonexistent');
    assert.equal(result.didDocument, null);
    assert.equal(result.didResolutionMetadata.error, 'notFound');
  });

  it('returns error for unknown country', () => {
    const result = resolver.resolve('did:pki:zz:some-ca');
    assert.equal(result.didDocument, null);
    assert.equal(result.didResolutionMetadata.error, 'notFound');
  });

  it('lists all resolvable DIDs', () => {
    const dids = resolver.listDids();
    assert.ok(dids.length > 0);
    assert.ok(dids.includes('did:pki:cr:raiz-nacional'));
    assert.ok(dids.includes('did:pki:cr:sinpe:persona-fisica'));
  });

  it('DID Document has correct @context', () => {
    const result = resolver.resolve('did:pki:cr:raiz-nacional');
    assert.deepStrictEqual(result.didDocument!['@context'], [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
      'https://spec.attestto.com/v1/pki.jsonld',
    ]);
  });

  it('root CA has childDids', () => {
    const result = resolver.resolve('did:pki:cr:raiz-nacional');
    assert.ok(result.didDocument!.pkiMetadata.childDids);
    assert.ok(result.didDocument!.pkiMetadata.childDids!.length > 0);
  });

  it('issuing CA has parentDid and rootDid', () => {
    const result = resolver.resolve('did:pki:cr:sinpe:persona-fisica');
    assert.ok(result.didDocument!.pkiMetadata.parentDid);
    assert.equal(result.didDocument!.pkiMetadata.rootDid, 'did:pki:cr:raiz-nacional');
  });
});
