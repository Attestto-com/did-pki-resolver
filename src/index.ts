export { parseDid, formatDid } from './parser.js';
export { normalizeCN, deriveDid, derivePathKey } from './normalize.js';
export { TrustRegistry } from './registry.js';
export { buildDidDocument } from './document.js';
export { DidPkiResolver } from './resolver.js';
export { COUNTRY_CONFIGS, getCountryConfig } from './countries.js';
export type {
  ParsedDid,
  CertificateEntry,
  CountryManifest,
  RegistryEntry,
  DidDocument,
  DidDocumentMetadata,
  DidResolutionResult,
  VerificationMethod,
  ServiceEndpoint,
  GenerationMeta,
  PkiMetadata,
  CountryConfig,
} from './types.js';
