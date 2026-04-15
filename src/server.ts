import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import { TrustRegistry } from './registry.js';
import { DidPkiResolver } from './resolver.js';

const PORT = parseInt(process.env.PORT ?? '8080', 10);
const TRUST_STORE = process.env.TRUST_STORE_PATH ?? join(import.meta.dirname, '..', 'trust-store', 'countries');

// Initialize resolver
const registry = new TrustRegistry(TRUST_STORE);
registry.load();
const resolver = new DidPkiResolver(registry);

console.log(`[did:pki] Loaded ${resolver.listDids().length} DIDs from trust store`);

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Accept');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      methods: ['did:pki'],
      dids: resolver.listDids().length,
    }));
    return;
  }

  // Universal Resolver driver endpoint
  // GET /1.0/identifiers/{did}
  const match = req.url?.match(/^\/1\.0\/identifiers\/(.+)$/);
  if (req.method === 'GET' && match) {
    const did = decodeURIComponent(match[1]);

    const result = resolver.resolve(did);

    const statusCode = result.didResolutionMetadata.error
      ? (result.didResolutionMetadata.error === 'notFound' ? 404
        : result.didResolutionMetadata.error === 'invalidDid' ? 400
        : 500)
      : 200;

    res.writeHead(statusCode, {
      'Content-Type': 'application/ld+json',
    });
    res.end(JSON.stringify(result));
    return;
  }

  // List all resolvable DIDs
  if (req.method === 'GET' && req.url === '/1.0/identifiers') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ dids: resolver.listDids() }));
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
  console.log(`[did:pki] Universal Resolver driver listening on port ${PORT}`);
  console.log(`[did:pki] Resolve: GET /1.0/identifiers/did:pki:cr:raiz-nacional`);
});
