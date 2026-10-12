import { describe, expect, it } from 'vitest';
import type { MessageAnalysis } from '@phishlens/shared';
import { displayedHost, extractLinks, findBrandClaims, findPatterns, htmlToText, looksLikeHtml, messageHeuristics } from '../../src/analyzers/message/index.js';
import { brands, codes } from '../helpers.js';

function analyse(raw: string) {
  const isHtml = looksLikeHtml(raw);
  const text = isHtml ? htmlToText(raw) : raw;
  const a: MessageAnalysis = { length: raw.length, isHtml, links: extractLinks(raw, isHtml), patternHits: findPatterns(text), claimedBrands: [] };
  return { a, indicators: messageHeuristics(text, raw, a) };
}

describe('benign messages', () => {
  it('ordinary business mail produces no risk indicators', () => {
    const { indicators } = analyse(
      'Hi Sam,\n\nThanks for the notes from yesterday. I updated the project plan and the password policy section is now in the wiki. ' +
        'Can we review the budget on Thursday? The meeting room is booked.\n\nBest,\nAlex',
    );
    expect(indicators.filter((i) => i.polarity !== 'neutral' && i.severity !== 'info')).toEqual([]);
  });

  it('does not treat bare keywords as patterns', () => {
    expect(findPatterns('password account login verify urgent bank invoice')).toEqual([]);
  });

  it('a legitimate newsletter with tracked links does not raise link mismatches', () => {
    const { a } = analyse('<p>Read <a href="https://click.news.example.org/t/abc">our latest article</a></p>');
    expect(a.links).toHaveLength(1);
    expect(a.links[0]!.mismatch).toBe(false);
  });

  it('a displayed URL that matches its destination is not a mismatch', () => {
    const { a } = analyse('<a href="https://www.example.com/help">www.example.com/help</a>');
    expect(a.links[0]).toMatchObject({ displayedHost: 'www.example.com', mismatch: false });
  });
});

describe('risk patterns', () => {
  it('detects urgency with evidence quoted from the text', () => {
    const { indicators } = analyse('Your account requires immediate verification. Please confirm within 24 hours.');
    const urgency = indicators.filter((i) => i.title === 'Urgency language detected');
    expect(urgency.length).toBeGreaterThan(0);
    expect(urgency[0]!.evidence).toMatch(/immediate verification|within 24 hours/);
    expect(urgency[0]!.description).toMatch(/time pressure|immediate action/);
  });

  it('detects credential requests', () => {
    expect(codes(analyse('Please verify your password to continue using the service.').indicators)).toContain('MESSAGE_CREDENTIAL_REQUEST');
    expect(codes(analyse('Your mailbox password expires today.').indicators)).toContain('MESSAGE_CREDENTIAL_REQUEST');
    expect(codes(analyse('Enter the one-time code we sent you on the page below.').indicators)).toContain('MESSAGE_CREDENTIAL_REQUEST');
  });

  it('detects payment requests, gift cards and bank-detail changes', () => {
    expect(codes(analyse('Please buy 5 Apple gift cards and send me the codes.').indicators)).toContain('MESSAGE_PAYMENT_GIFT_CARDS');
    expect(codes(analyse('We have new bank details for all future invoices.').indicators)).toContain('MESSAGE_PAYMENT_BANK_CHANGE');
    expect(codes(analyse('Kindly process a wire transfer today.').indicators)).toContain('MESSAGE_PAYMENT_TRANSFER');
  });

  it('detects threats, secrecy and impersonation of internal departments', () => {
    const out = codes(analyse('This is the IT Department. Your mailbox will be suspended. Keep this confidential.').indicators);
    expect(out).toEqual(expect.arrayContaining(['MESSAGE_IMPERSONATION_DEPARTMENT', 'MESSAGE_THREAT_ACCOUNT_RESTRICTION', 'MESSAGE_SECRECY']));
  });

  it('scores the combination of techniques separately from individual phrases', () => {
    const { indicators } = analyse(
      'Dear Customer, your account has been limited. Verify your password within 24 hours or it will be closed. Do not share this with anyone.',
    );
    const combo = indicators.find((i) => i.code === 'MESSAGE_SE_COMBINATION');
    expect(combo?.severity).toBe('medium');
    expect(combo?.title).toMatch(/combines [3-9]/);
  });

  it('does not create a combination indicator from a single technique', () => {
    expect(codes(analyse('Please review the attached invoice and pay the outstanding balance.').indicators)).not.toContain('MESSAGE_SE_COMBINATION');
  });
});

describe('links', () => {
  it('detects mismatched displayed URLs in HTML anchors', () => {
    const { a, indicators } = analyse('<p>Sign in at <a href="https://paypal-verify.example/login">https://www.paypal.com/signin</a></p>');
    expect(a.links[0]).toMatchObject({ displayedHost: 'www.paypal.com', hrefHost: 'paypal-verify.example', mismatch: true });
    expect(indicators.find((i) => i.code === 'LINK_DISPLAY_MISMATCH')).toMatchObject({ severity: 'high', category: 'LINK' });
    // The displayed text is not itself a link and must not be extracted (or probed) as one.
    expect(a.links.map((l) => l.href)).toEqual(['https://paypal-verify.example/login']);
  });

  it('detects mismatched markdown links and extracts plain URLs', () => {
    const links = extractLinks('See [www.bank.com](https://evil.example/x) and also https://plain.example/y.', false);
    expect(links.map((l) => [l.href, l.mismatch])).toEqual([
      ['https://evil.example/x', true],
      ['https://plain.example/y', false],
    ]);
  });

  it('decodes entities in hrefs and ignores mailto links', () => {
    const links = extractLinks('<a href="https://a.example/?a=1&amp;b=2">x</a><a href="mailto:x@y.example">mail</a>', true);
    expect(links.map((l) => l.href)).toEqual(['https://a.example/?a=1&b=2']);
  });

  it('reads only link text a human would see as a host', () => {
    expect(displayedHost('Click here')).toBeNull();
    expect(displayedHost('https://accounts.google.com/x')).toBe('accounts.google.com');
    expect(displayedHost('report.pdf')).toBeNull();
  });
});

describe('obfuscation and claims', () => {
  it('detects zero-width character obfuscation', () => {
    expect(codes(analyse('Ve​ri​fy your pa​ss​word').indicators)).toContain('MESSAGE_INVISIBLE_CHARACTERS');
  });

  it('detects hidden HTML text', () => {
    expect(codes(analyse('<div style="display:none">harmless padding</div><p>Hi</p>').indicators)).toContain('MESSAGE_HIDDEN_HTML_TEXT');
  });

  it('finds brand claims in context, not bare mentions', () => {
    expect(findBrandClaims('Your PayPal account has been limited. — The PayPal Team', brands).map((c) => c.brand.name)).toEqual(['PayPal']);
    expect(findBrandClaims('I paid with paypal last week.', brands)).toEqual([]);
  });
});
