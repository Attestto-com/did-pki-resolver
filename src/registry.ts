import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { CountryManifest, CertificateEntry, RegistryEntry } from './types.js';
import { derivePathKey } from './normalize.js';

/**
 * Trust Registry — indexes certificates from attestto-trust and maps them
 * to did:pki identifiers via the normalization/derivation algorithm.
 */
export class TrustRegistry {
  /** Map: "cr:sinpe:persona-fisica" → RegistryEntry[] (multiple generations) */
  private entries = new Map<string, RegistryEntry[]>();

  /** Map: DID string → RegistryEntry[] */
  private byDid = new Map<string, RegistryEntry[]>();

  /** Map: country code → all entries */
  private byCountry = new Map<string, RegistryEntry[]>();

  /** Base path to attestto-trust/countries/ */
  private trustStorePath: string;

  constructor(trustStorePath: string) {
    this.trustStorePath = resolve(trustStorePath);
  }

  /**
   * Load all countries from the trust store.
   * Scans countries/ directory for manifest.json files.
   */
  load(): void {
    const countriesDir = this.trustStorePath;
    if (!existsSync(countriesDir)) {
      throw new Error(`Trust store not found: ${countriesDir}`);
    }

    const countryDirs = readdirSync(countriesDir, { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name.length === 2)
      .map(d => d.name);

    for (const cc of countryDirs) {
      this.loadCountry(cc);
    }
  }

  /**
   * Load a specific country's manifest and index certificates.
   */
  loadCountry(countryCode: string): void {
    const cc = countryCode.toLowerCase();
    const manifestPath = join(this.trustStorePath, cc, 'current', 'manifest.json');

    if (!existsSync(manifestPath)) return;

    const manifest: CountryManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    const entries: RegistryEntry[] = [];

    // First pass: build hierarchy by checking issuer chains
    const certsBySubject = new Map<string, CertificateEntry[]>();
    for (const cert of manifest.certificates) {
      const existing = certsBySubject.get(cert.subject) ?? [];
      existing.push(cert);
      certsBySubject.set(cert.subject, existing);
    }

    // Identify root cert (self-signed)
    const rootCert = manifest.certificates.find(c => c.role === 'root');
    const rootPathKey = rootCert ? derivePathKey(rootCert.subject) : '';
    const rootDid = `did:pki:${cc}:${rootPathKey}`;

    for (const cert of manifest.certificates) {
      const pathKey = derivePathKey(cert.subject);
      const did = `did:pki:${cc}:${pathKey}`;
      const pemPath = join(this.trustStorePath, cc, 'current', cert.file);

      // Determine level
      let level: 'root' | 'policy' | 'issuing';
      if (cert.role === 'root') {
        level = 'root';
      } else if (cert.issuer === rootCert?.subject) {
        level = 'policy';
      } else {
        level = 'issuing';
      }

      // Determine parent DID
      let parentDid: string | undefined;
      if (level !== 'root') {
        const parentPathKey = derivePathKey(cert.issuer);
        parentDid = `did:pki:${cc}:${parentPathKey}`;
      }

      const entry: RegistryEntry = {
        did,
        countryCode: cc,
        caPath: pathKey.split(':'),
        cert,
        pemPath,
        level,
        parentDid,
        rootDid,
      };

      entries.push(entry);

      // Index by lookup key (country:path)
      const lookupKey = `${cc}:${pathKey}`;
      const existing = this.entries.get(lookupKey) ?? [];
      existing.push(entry);
      this.entries.set(lookupKey, existing);

      // Index by DID
      const byDidExisting = this.byDid.get(did) ?? [];
      byDidExisting.push(entry);
      this.byDid.set(did, byDidExisting);
    }

    // Second pass: populate childDids on root/policy entries
    for (const entry of entries) {
      if (entry.level === 'root' || entry.level === 'policy') {
        const children = entries
          .filter(e => e.parentDid === entry.did && e.did !== entry.did)
          .map(e => e.did);
        // Deduplicate (multiple generations of same CA)
        entry.childDids = [...new Set(children)];
      }
    }

    this.byCountry.set(cc, entries);
  }

  /**
   * Look up registry entries by country code and ca-path.
   * Returns all generations (certificate instances) matching the path.
   */
  lookup(countryCode: string, caPath: string[]): RegistryEntry[] {
    const key = `${countryCode.toLowerCase()}:${caPath.join(':')}`;
    return this.entries.get(key) ?? [];
  }

  /**
   * Look up by full DID string.
   */
  lookupByDid(did: string): RegistryEntry[] {
    return this.byDid.get(did) ?? [];
  }

  /** Get all indexed DIDs */
  getAllDids(): string[] {
    return [...this.byDid.keys()];
  }

  /** Get all entries for a country */
  getCountryEntries(countryCode: string): RegistryEntry[] {
    return this.byCountry.get(countryCode.toLowerCase()) ?? [];
  }

  /** Read the PEM content for a registry entry */
  readPem(entry: RegistryEntry): string {
    return readFileSync(entry.pemPath, 'utf-8');
  }
}
