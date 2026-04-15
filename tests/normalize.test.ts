import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeCN, deriveDid, derivePathKey } from '../src/normalize.js';

describe('normalizeCN', () => {
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

  it('normalizes Spain FNMT root', () => {
    assert.deepStrictEqual(
      normalizeCN('AC RAIZ FNMT-RCM'),
      ['raiz-fnmt-rcm']
    );
  });

  it('normalizes Brazil ICP root', () => {
    assert.deepStrictEqual(
      normalizeCN('AC Raiz ICP-Brasil v10'),
      ['raiz-icp-brasil']
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

  it('normalizes BCCR agente electronico', () => {
    // This is a special case — not a standard CA prefix
    assert.deepStrictEqual(
      normalizeCN('BANCO CENTRAL DE COSTA RICA (AGENTE ELECTRONICO)'),
      ['banco-central-de-costa-rica-(agente-electronico)']
    );
  });
});

describe('deriveDid', () => {
  it('derives CR root DID', () => {
    assert.equal(
      deriveDid('CR', 'CA RAIZ NACIONAL - COSTA RICA v2'),
      'did:pki:cr:raiz-nacional'
    );
  });

  it('derives CR issuing CA DID', () => {
    assert.equal(
      deriveDid('CR', 'CA SINPE - PERSONA FISICA v2'),
      'did:pki:cr:sinpe:persona-fisica'
    );
  });
});

describe('derivePathKey', () => {
  it('derives path key for registry lookup', () => {
    assert.equal(
      derivePathKey('CA SINPE - PERSONA FISICA v2'),
      'sinpe:persona-fisica'
    );
  });

  it('derives path key for root', () => {
    assert.equal(
      derivePathKey('CA RAIZ NACIONAL - COSTA RICA v2'),
      'raiz-nacional'
    );
  });
});
