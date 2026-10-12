import { describe, expect, it } from 'vitest';
import { normalizeDomainInput, parseDomain } from '../../src/analyzers/domain/parseDomain.js';
import { findBrandMatches } from '../../src/analyzers/domain/lookalike.js';
import { domainHeuristics } from '../../src/analyzers/domain/heuristics.js';
import { isMixedScript, skeleton } from '../../src/analyzers/domain/confusables.js';
import { brands, codes, lists } from '../helpers.js';

const analyse = (host: string) => {
  const d = parseDomain(host);
  d.brandMatches = findBrandMatches(d, brands);
  return { d, indicators: domainHeuristics(d, lists) };
};

describe('domain extraction', () => {
  it('splits subdomain, registrable domain and TLD', () => {
    const d = parseDomain('a.b.login.example.co.uk');
    expect(d).toMatchObject({
      subdomain: 'a.b.login',
      registrableDomain: 'example.co.uk',
      publicSuffix: 'co.uk',
      tld: 'uk',
      subdomainDepth: 3,
      isIp: false,
    });
  });

  it('handles apex domains', () => {
    expect(parseDomain('example.com')).toMatchObject({ subdomain: null, registrableDomain: 'example.com', subdomainDepth: 0 });
  });

  it('identifies IPs', () => {
    expect(parseDomain('203.0.113.9').isIp).toBe(true);
  });

  it('normalises domain input from URLs, emails, defanged text and IDN', () => {
    expect(normalizeDomainInput('https://Example.COM/path?q')).toBe('example.com');
    expect(normalizeDomainInput('user@mail.example.org')).toBe('mail.example.org');
    expect(normalizeDomainInput('evil[.]example')).toBe('evil.example');
    expect(normalizeDomainInput('bücher.example')).toBe('xn--bcher-kva.example');
    expect(normalizeDomainInput('not a domain')).toBeNull();
    expect(normalizeDomainInput('-bad-.com')).toBeNull();
  });
});

describe('confusables', () => {
  it('folds homoglyphs and digit substitutions to the same skeleton', () => {
    expect(skeleton('pаypal')).toBe(skeleton('paypal')); // Cyrillic а
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('rnicrosoft')).toBe(skeleton('microsoft'));
    expect(skeleton('g00gle')).toBe(skeleton('google'));
  });

  it('detects mixed-script labels but allows normal CJK combinations', () => {
    expect(isMixedScript('pаypal')).toBe(true);
    expect(isMixedScript('bücher')).toBe(false);
    expect(isMixedScript('日本語ドメイン')).toBe(false);
  });
});

describe('brand lookalike heuristic', () => {
  it('recognises official brand domains as benign context', () => {
    const { indicators } = analyse('www.paypal.com');
    expect(indicators.map((i) => [i.code, i.polarity])).toEqual([['DOMAIN_OFFICIAL_BRAND', 'benign']]);
  });

  it('detects an official domain used as a subdomain', () => {
    expect(codes(analyse('paypal.com.account-check.example').indicators)).toContain('LOOKALIKE_OFFICIAL_AS_SUBDOMAIN');
  });

  it('detects digit-substitution and Cyrillic homoglyphs', () => {
    expect(codes(analyse('paypa1.com').indicators)).toContain('LOOKALIKE_HOMOGLYPH');
    expect(codes(analyse('xn--pypal-4ve.com').indicators)).toContain('LOOKALIKE_HOMOGLYPH');
  });

  it('detects typosquats', () => {
    expect(codes(analyse('paypall.com').indicators)).toContain('LOOKALIKE_TYPOSQUAT');
    expect(codes(analyse('microsfot.com').indicators)).toContain('LOOKALIKE_TYPOSQUAT');
  });

  it('detects brand keywords in unrelated domains and subdomains', () => {
    expect(codes(analyse('paypal-secure-login.example').indicators)).toContain('LOOKALIKE_BRAND_KEYWORD');
    expect(codes(analyse('paypal.verify-now.example').indicators)).toContain('LOOKALIKE_BRAND_KEYWORD');
  });

  it('marks the same brand name on another TLD as a weaker tld-swap', () => {
    const ind = analyse('paypal.example').indicators.find((i) => i.code === 'LOOKALIKE_TLD_SWAP');
    expect(ind?.severity).toBe('medium');
  });

  it('does not match short keywords as substrings of unrelated words', () => {
    expect(analyse('adhlerfoods.com').indicators).toEqual([]);
    expect(analyse('shipping-updates.com').indicators).toEqual([]);
  });

  it('does not flag unrelated ordinary domains', () => {
    for (const host of ['example.com', 'github.com', 'wikipedia.org', 'bbc.co.uk']) {
      expect(analyse(host).indicators).toEqual([]);
    }
  });

  it('labels lookalike findings as heuristics', () => {
    for (const i of analyse('paypa1-login.com').indicators) expect(i.description).toMatch(/heuristic/i);
  });

  it('produces nothing when no brands are configured', () => {
    const d = parseDomain('paypa1.com');
    expect(findBrandMatches(d, [])).toEqual([]);
  });
});

describe('structural domain heuristics', () => {
  it('flags mixed-script IDNs not already explained by a brand match', () => {
    expect(codes(analyse('xn--80ak6aa92e.com').indicators)).not.toContain('DOMAIN_MIXED_SCRIPT_IDN'); // all-Cyrillic "аррӏе"
    const mixed = analyse('xn--exmple-4nf.com'); // "exаmple" with a Cyrillic а
    expect(codes(mixed.indicators)).toContain('DOMAIN_MIXED_SCRIPT_IDN');
  });

  it('records single-script IDNs as neutral context', () => {
    const i = analyse('xn--bcher-kva.example').indicators.find((x) => x.code === 'DOMAIN_IDN');
    expect(i?.severity).toBe('info');
    expect(codes(analyse('xn--bcher-kva.example').indicators)).toEqual(['DOMAIN_IDN']);
  });

  it('flags a subdomain formatted like another domain', () => {
    expect(codes(analyse('secure.bank.com.verify-account.example').indicators)).toContain('DOMAIN_DOMAIN_LIKE_SUBDOMAIN');
  });

  it('flags deep nesting, many hyphens, numeric names and elevated-abuse TLDs at low severity', () => {
    const all = [
      ...analyse('a.b.c.d.e.example.com').indicators,
      ...analyse('secure-account-verify-login.example').indicators,
      ...analyse('83749283.example').indicators,
      ...analyse('invoice.zip').indicators,
    ];
    expect(codes(all)).toEqual(
      expect.arrayContaining(['DOMAIN_DEEP_SUBDOMAIN', 'DOMAIN_MANY_HYPHENS', 'DOMAIN_NUMERIC', 'DOMAIN_ELEVATED_ABUSE_TLD']),
    );
    for (const i of all) expect(i.severity).toBe('low');
  });

  it('notes shared hosting platforms', () => {
    expect(codes(analyse('login-portal.github.io').indicators)).toContain('DOMAIN_SHARED_HOSTING');
  });
});
