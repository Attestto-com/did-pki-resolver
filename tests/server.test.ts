import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { TrustRegistry } from '../src/registry.js';
import { DidPkiResolver } from '../src/resolver.js';

const TRUST_STORE = join(import.meta.dirname, '..', '..', 'attestto-trust', 'countries');
const TEST_PORT = 9876;

/** Minimal HTTP server matching the Universal Resolver driver interface */
function createDriverServer(resolver: DidPkiResolver): Server {
  return createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', methods: ['did:pki'] }));
      return;
    }

    const match = req.url?.match(/^\/1\.0\/identifiers\/(.+)$/);
    if (req.method === 'GET' && match) {
      const did = decodeURIComponent(match[1]);
      const result = resolver.resolve(did);
      const statusCode = result.didResolutionMetadata.error
        ? (result.didResolutionMetadata.error === 'notFound' ? 404
          : result.didResolutionMetadata.error === 'invalidDid' ? 400
          : 500)
        : 200;
      res.writeHead(statusCode, { 'Content-Type': 'application/ld+json' });
      res.end(JSON.stringify(result));
      return;
    }

    res.writeHead(404);
    res.end();
  });
}

async function fetch(path: string): Promise<{ status: number; body: any }> {
  const res = await globalThis.fetch(`http://localhost:${TEST_PORT}${path}`);
  const body = await res.json();
  return { status: res.status, body };
}

describe('Universal Resolver Driver HTTP', () => {
  let server: Server;

  before(async () => {
    const registry = new TrustRegistry(TRUST_STORE);
    registry.load();
    const resolver = new DidPkiResolver(registry);
    server = createDriverServer(resolver);
    await new Promise<void>(resolve => server.listen(TEST_PORT, resolve));
  });

  after(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
  });

  it('GET /health returns ok', async () => {
    const { status, body } = await fetch('/health');
    assert.equal(status, 200);
    assert.equal(body.status, 'ok');
    assert.deepStrictEqual(body.methods, ['did:pki']);
  });

  it('GET /1.0/identifiers/did:pki:cr:raiz-nacional returns DID Document', async () => {
    const { status, body } = await fetch('/1.0/identifiers/did:pki:cr:raiz-nacional');
    assert.equal(status, 200);
    assert.equal(body['@context'], 'https://w3id.org/did-resolution/v1');
    assert.equal(body.didDocument.id, 'did:pki:cr:raiz-nacional');
    assert.equal(body.didDocument.pkiMetadata.level, 'root');
    assert.ok(body.didDocument.verificationMethod.length >= 1);
  });

  it('GET /1.0/identifiers/did:pki:cr:sinpe:persona-fisica returns issuing CA with endEntityHints', async () => {
    const { status, body } = await fetch('/1.0/identifiers/did:pki:cr:sinpe:persona-fisica');
    assert.equal(status, 200);
    assert.equal(body.didDocument.pkiMetadata.level, 'issuing');
    assert.ok(body.didDocument.pkiMetadata.endEntityHints);
    assert.equal(body.didDocument.pkiMetadata.endEntityHints.nationalIdFormat, 'CR-cedula');
  });

  it('returns 404 for unknown DID', async () => {
    const { status, body } = await fetch('/1.0/identifiers/did:pki:cr:nonexistent');
    assert.equal(status, 404);
    assert.equal(body.didResolutionMetadata.error, 'notFound');
    assert.equal(body.didDocument, null);
  });

  it('returns 400 for invalid DID', async () => {
    const { status, body } = await fetch('/1.0/identifiers/did:web:example.com');
    assert.equal(status, 400);
    assert.equal(body.didResolutionMetadata.error, 'invalidDid');
  });

  it('response Content-Type is application/ld+json', async () => {
    const res = await globalThis.fetch(`http://localhost:${TEST_PORT}/1.0/identifiers/did:pki:cr:raiz-nacional`);
    assert.equal(res.headers.get('content-type'), 'application/ld+json');
  });
});
