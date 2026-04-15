import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseDid, formatDid } from '../src/parser.js';

describe('parseDid', () => {
  it('parses a simple root CA DID', () => {
    const result = parseDid('did:pki:cr:raiz-nacional');
    assert.deepStrictEqual(result, {
      method: 'pki',
      countryCode: 'cr',
      caPath: ['raiz-nacional'],
      generation: undefined,
    });
  });

  it('parses a two-segment DID', () => {
    const result = parseDid('did:pki:cr:sinpe:persona-fisica');
    assert.deepStrictEqual(result, {
      method: 'pki',
      countryCode: 'cr',
      caPath: ['sinpe', 'persona-fisica'],
      generation: undefined,
    });
  });

  it('parses a DID with generation suffix', () => {
    const result = parseDid('did:pki:cr:sinpe:persona-fisica:2023');
    assert.deepStrictEqual(result, {
      method: 'pki',
      countryCode: 'cr',
      caPath: ['sinpe', 'persona-fisica'],
      generation: '2023',
    });
  });

  it('parses EU QTSP DID', () => {
    const result = parseDid('did:pki:eu:de:d-trust');
    assert.deepStrictEqual(result, {
      method: 'pki',
      countryCode: 'eu',
      caPath: ['de', 'd-trust'],
      generation: undefined,
    });
  });

  it('parses deep hierarchy DID', () => {
    const result = parseDid('did:pki:br:icp:serpro:rfb');
    assert.deepStrictEqual(result, {
      method: 'pki',
      countryCode: 'br',
      caPath: ['icp', 'serpro', 'rfb'],
      generation: undefined,
    });
  });

  it('rejects invalid method', () => {
    assert.equal(parseDid('did:web:example.com'), null);
  });

  it('rejects missing path', () => {
    assert.equal(parseDid('did:pki:cr'), null);
  });

  it('rejects empty segments', () => {
    assert.equal(parseDid('did:pki:cr::raiz'), null);
  });

  it('rejects uppercase country code', () => {
    assert.equal(parseDid('did:pki:CR:raiz-nacional'), null);
  });

  it('rejects invalid characters in segment', () => {
    assert.equal(parseDid('did:pki:cr:raiz_nacional'), null);
  });
});

describe('formatDid', () => {
  it('formats a simple DID', () => {
    assert.equal(
      formatDid({ method: 'pki', countryCode: 'cr', caPath: ['raiz-nacional'] }),
      'did:pki:cr:raiz-nacional'
    );
  });

  it('formats a DID with generation', () => {
    assert.equal(
      formatDid({ method: 'pki', countryCode: 'cr', caPath: ['sinpe', 'persona-fisica'], generation: '2023' }),
      'did:pki:cr:sinpe:persona-fisica:2023'
    );
  });
});
