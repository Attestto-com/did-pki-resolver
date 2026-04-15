import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeCN, deriveDid, derivePathKey, derivePathSegments } from '../src/normalize.js';

describe('normalizeCN (CN-only, no O field)', () => {
  it('normalizes CR root CA', () => {
    assert.deepStrictEqual(
      normalizeCN('CA RAIZ NACIONAL - COSTA RICA v2'),
      ['raiz-nacional']
    );
  });

  it('normalizes CR policy CA persona fisica', () => {
    assert.deepStrictEqual(
      normalizeCN('CA POLITICA PERSONA FISICA - COSTA RICA v2'),
      ['politica', 'persona-fisica']
    );
  });

  it('normalizes CR issuing CA SINPE persona fisica', () => {
    assert.deepStrictEqual(
      normalizeCN('CA SINPE - PERSONA FISICA v2'),
      ['sinpe', 'persona-fisica']
    );
  });

  it('normalizes CR policy CA persona juridica', () => {
    assert.deepStrictEqual(
      normalizeCN('CA POLITICA PERSONA JURIDICA - COSTA RICA v2'),
      ['politica', 'persona-juridica']
    );
  });

  it('normalizes CR issuing CA SINPE persona juridica', () => {
    assert.deepStrictEqual(
      normalizeCN('CA SINPE - PERSONA JURIDICA v2'),
      ['sinpe', 'persona-juridica']
    );
  });

  it('handles accented characters', () => {
    assert.deepStrictEqual(
      normalizeCN('CA POLÍTICA PERSONA FÍSICA'),
      ['politica', 'persona-fisica']
    );
  });

  it('strips version suffixes', () => {
    assert.deepStrictEqual(
      normalizeCN('CA RAIZ NACIONAL - COSTA RICA v2'),
      ['raiz-nacional']
    );
  });

  it('strips generation suffixes', () => {
    assert.deepStrictEqual(
      normalizeCN('Federal Common Policy CA G2'),
      ['federal-common-policy-ca']
    );
  });
});

describe('derivePathSegments (with O field)', () => {
  // Costa Rica — O="BCCR" is country authority, OMITTED
  it('CR: O=BCCR (country authority) → omitted, uses CN only', () => {
    assert.deepStrictEqual(
      derivePathSegments('cr', 'CA RAIZ NACIONAL - COSTA RICA v2', 'BCCR'),
      ['raiz-nacional']
    );
  });

  it('CR: O=BCCR, CN=SINPE issuing → omitted, CN-only', () => {
    assert.deepStrictEqual(
      derivePathSegments('cr', 'CA SINPE - PERSONA FISICA v2', 'BCCR'),
      ['sinpe', 'persona-fisica']
    );
  });

  // Spain — O="FNMT-RCM" is NOT country authority → first segment
  it('ES: FNMT root → fnmt:raiz', () => {
    assert.deepStrictEqual(
      derivePathSegments('es', 'AC RAIZ FNMT-RCM', 'FNMT-RCM'),
      ['fnmt', 'raiz']
    );
  });

  it('ES: FNMT representacion → fnmt:representacion', () => {
    assert.deepStrictEqual(
      derivePathSegments('es', 'AC FNMT Usuarios - Representación', 'FNMT-RCM'),
      ['fnmt', 'usuarios', 'representacion']
    );
  });

  it('ES: FNMT componentes → fnmt:componentes', () => {
    assert.deepStrictEqual(
      derivePathSegments('es', 'AC Componentes Informáticos', 'FNMT-RCM'),
      ['fnmt', 'componentes-informaticos']
    );
  });

  // Brazil — O="ICP-Brasil" has known abbreviation → "icp"
  it('BR: ICP-Brasil root → icp:raiz', () => {
    assert.deepStrictEqual(
      derivePathSegments('br', 'AC Raiz ICP-Brasil v10', 'ICP-Brasil'),
      ['icp', 'raiz']
    );
  });

  it('BR: SERPRO under ICP → serpro:rfb', () => {
    assert.deepStrictEqual(
      derivePathSegments('br', 'AC SERPRO RFB v5', 'SERPRO'),
      ['serpro', 'rfb']
    );
  });

  // US — O="U.S. Government" is country authority → omitted
  it('US: O=U.S. Government (country authority) → omitted', () => {
    assert.deepStrictEqual(
      derivePathSegments('us', 'Federal Common Policy CA G2', 'U.S. Government'),
      ['federal-common-policy-ca']
    );
  });

  // No O field → falls back to CN-only
  it('no O field → CN-only derivation', () => {
    assert.deepStrictEqual(
      derivePathSegments('cr', 'CA SINPE - PERSONA FISICA v2'),
      ['sinpe', 'persona-fisica']
    );
  });
});

describe('deriveDid', () => {
  it('derives CR root DID (O=BCCR omitted)', () => {
    assert.equal(
      deriveDid('CR', 'CA RAIZ NACIONAL - COSTA RICA v2', 'BCCR'),
      'did:pki:cr:raiz-nacional'
    );
  });

  it('derives CR issuing CA DID', () => {
    assert.equal(
      deriveDid('CR', 'CA SINPE - PERSONA FISICA v2', 'BCCR'),
      'did:pki:cr:sinpe:persona-fisica'
    );
  });

  it('derives ES FNMT root DID', () => {
    assert.equal(
      deriveDid('ES', 'AC RAIZ FNMT-RCM', 'FNMT-RCM'),
      'did:pki:es:fnmt:raiz'
    );
  });

  it('derives BR ICP root DID', () => {
    assert.equal(
      deriveDid('BR', 'AC Raiz ICP-Brasil v10', 'ICP-Brasil'),
      'did:pki:br:icp:raiz'
    );
  });
});

describe('derivePathKey', () => {
  it('derives path key for registry lookup (CN-only)', () => {
    assert.equal(
      derivePathKey('CA SINPE - PERSONA FISICA v2'),
      'sinpe:persona-fisica'
    );
  });

  it('derives path key with O field', () => {
    assert.equal(
      derivePathKey('AC RAIZ FNMT-RCM', 'FNMT-RCM', 'es'),
      'fnmt:raiz'
    );
  });

  it('derives path key for root (CN-only)', () => {
    assert.equal(
      derivePathKey('CA RAIZ NACIONAL - COSTA RICA v2'),
      'raiz-nacional'
    );
  });
});
