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

  it('returns JWK public keys with x5t fingerprint', () => {
    const result = resolver.resolve('did:pki:cr:raiz-nacional');
    const vm = result.didDocument!.verificationMethod[0];
    assert.equal(vm.type, 'JsonWebKey2020');
    assert.ok(vm.publicKeyJwk.kty);
    assert.ok(vm.publicKeyJwk.x5t);
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
