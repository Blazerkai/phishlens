import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  decodeEncodedWords,
  parseAddress,
  parseAddressList,
  parseAuthenticationResults,
  parseDkimSignature,
  parseEmailHeaders,
  parseReceived,
  splitHeaders,
} from '../../src/analyzers/email/parseHeaders.js';
import { emailHeuristics } from '../../src/analyzers/email/heuristics.js';
import { brands, codes, lists } from '../helpers.js';

const fixture = (name: string) => fs.readFileSync(path.join(__dirname, '..', 'fixtures', name), 'utf8');
const heur = (raw: string) => emailHeuristics(parseEmailHeaders(raw), { brands, lists });

describe('header block parsing', () => {
  it('unfolds continuation lines and stops at the body', () => {
    const h = splitHeaders('Subject: a\n  folded\nX-Test: 1\n\nBody: not a header');
    expect(h).toEqual([
      { name: 'Subject', value: 'a folded' },
      { name: 'X-Test', value: '1' },
    ]);
  });

  it('handles CRLF and leading blank lines', () => {
    expect(splitHeaders('\r\n\r\nFrom: a@b.example\r\nTo: c@d.example\r\n')).toHaveLength(2);
  });

  it('decodes RFC 2047 encoded words (B and Q)', () => {
    expect(decodeEncodedWords('=?UTF-8?B?WW91ciBNYXJjaCB1cGRhdGUg4pyT?=')).toBe('Your March update ✓');
    expect(decodeEncodedWords('=?ISO-8859-1?Q?Caf=E9_ouvert?=')).toBe('Café ouvert');
    expect(decodeEncodedWords('=?UTF-8?Q?a?= =?UTF-8?Q?b?=')).toBe('ab');
  });
});

describe('address parsing', () => {
  it.each([
    ['"Doe, Jane" <Jane.Doe@Example.com>', 'Doe, Jane', 'jane.doe@example.com', 'example.com'],
    ['Jane <jane@example.com>', 'Jane', 'jane@example.com', 'example.com'],
    ['<jane@example.com>', null, 'jane@example.com', 'example.com'],
    ['jane@example.com (Jane Doe)', 'Jane Doe', 'jane@example.com', 'example.com'],
    ['=?UTF-8?B?UGF5UGFs?= <x@y.example>', 'PayPal', 'x@y.example', 'y.example'],
  ])('%s', (raw, display, address, domain) => {
    expect(parseAddress(raw)).toMatchObject({ displayName: display, address, domain });
  });

  it('splits lists without breaking quoted commas', () => {
    expect(parseAddressList('"Doe, Jane" <j@x.example>, b@y.example').map((a) => a.address)).toEqual(['j@x.example', 'b@y.example']);
  });
});

describe('Received parsing', () => {
  it('extracts helo, rDNS, IP, by, with, id, for and date', () => {
    const h = parseReceived(
      'from mail-out.example.org (mail-out.example.org. [198.2.128.10]) by mx.google.com with ESMTPS id abc123 for <a@corp.example> (version=TLS1_3); Mon, 02 Mar 2026 09:15:06 -0800 (PST)',
    );
    expect(h).toMatchObject({
      from: 'mail-out.example.org',
      fromRdns: 'mail-out.example.org',
      fromIp: '198.2.128.10',
      by: 'mx.google.com',
      with: 'ESMTPS',
      id: 'abc123',
      for: 'a@corp.example',
      timestamp: '2026-03-02T17:15:06.000Z',
      ipIsPrivate: false,
    });
  });

  it('extracts IPv6 and Microsoft-style bare IPs, flags private hops', () => {
    expect(parseReceived('from a.example ([IPv6:2001:4860:4860::8888]) by b.example; Mon, 2 Mar 2026 10:00:00 +0000').fromIp).toBe('2001:4860:4860::8888');
    expect(parseReceived('from mail.x.example (45.133.1.20) by y.example with SMTP; Tue, 3 Mar 2026 08:01:10 +0000').fromIp).toBe('45.133.1.20');
    expect(parseReceived('from origin (unknown [10.0.0.5]) by relay; Wed, 4 Mar 2026 10:20:00 +0000').ipIsPrivate).toBe(true);
  });

  it('orders the chain oldest-first and computes delays', () => {
    const e = parseEmailHeaders(fixture('display-spoof.txt'));
    expect(e.received.map((r) => r.by)).toEqual(['relay.bulk-sender.example', 'mx.corp.example']);
    expect(e.received[1]!.delaySeconds).toBe(-1200);
  });
});

describe('Authentication-Results parsing', () => {
  it('parses a Google-style header with authserv-id, properties and policy comment', () => {
    const ar = parseAuthenticationResults(
      'mx.google.com; dkim=pass header.i=@example.org header.s=s1; spf=pass (google.com: domain of b@example.org designates 1.2.3.4) smtp.mailfrom=b@example.org; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.org',
    );
    expect(ar.authservId).toBe('mx.google.com');
    expect(ar.results.map((r) => [r.method, r.result])).toEqual([['dkim', 'pass'], ['spf', 'pass'], ['dmarc', 'pass']]);
    expect(ar.results[1]!.properties['smtp.mailfrom']).toBe('b@example.org');
    expect(ar.results[2]!.properties['comment.p']).toBe('reject');
  });

  it('parses a Microsoft-style header without authserv-id', () => {
    const ar = parseAuthenticationResults('spf=fail (sender IP is 45.133.1.20) smtp.mailfrom=paypal.com; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=paypal.com;compauth=fail reason=000');
    expect(ar.authservId).toBeNull();
    expect(ar.results.map((r) => [r.method, r.result])).toEqual([['spf', 'fail'], ['dkim', 'none'], ['dmarc', 'fail'], ['other', 'fail']]);
    expect(ar.results[2]!.properties.action).toBe('quarantine');
  });

  it('parses reason= and hardfail', () => {
    const ar = parseAuthenticationResults('mx.example; spf=hardfail reason="not permitted" smtp.mailfrom=x.example');
    expect(ar.results[0]).toMatchObject({ result: 'fail', reason: 'not permitted' });
  });

  it('parses DKIM-Signature tags', () => {
    expect(parseDkimSignature('v=1; a=rsa-sha256; d=Example.org; s=s1; h=from:to:subject; bh=x; b=y')).toMatchObject({
      domain: 'example.org',
      selector: 's1',
      algorithm: 'rsa-sha256',
      signedHeaders: ['from', 'to', 'subject'],
    });
  });
});

describe('full header analysis', () => {
  it('summarises a legitimate newsletter: everything passes and aligns', () => {
    const e = parseEmailHeaders(fixture('legit-gmail.txt'));
    expect(e.from).toMatchObject({ displayName: 'Example Newsletter', address: 'news@newsletter.example.org' });
    expect(e.subject).toBe('Your March update ✓');
    expect(e.summary).toMatchObject({ spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', spfAligned: true, dkimAligned: true });
    expect(e.returnPath?.domain).toBe('mail.newsletter.example.org');
    expect(e.dkimSignatures[0]!.domain).toBe('newsletter.example.org');

    const out = heur(fixture('legit-gmail.txt'));
    expect(out.filter((i) => i.severity !== 'info')).toEqual([]);
    expect(codes(out)).toEqual(expect.arrayContaining(['EMAIL_SPF_PASS', 'EMAIL_DKIM_PASS', 'EMAIL_DMARC_PASS']));
    expect(out.find((i) => i.code === 'EMAIL_DMARC_PASS')!.polarity).toBe('benign');
  });

  it('trusts only the top-most Authentication-Results header', () => {
    const e = parseEmailHeaders(fixture('spoof-m365.txt'));
    expect(e.summary).toMatchObject({ spf: 'fail', dkim: 'none', dmarc: 'fail' });
    expect(codes(heur(fixture('spoof-m365.txt')))).toContain('EMAIL_MULTIPLE_AUTHSERV');
  });

  it('explains a spoofed brand with DMARC failure and a free-mail Reply-To', () => {
    const out = heur(fixture('spoof-m365.txt'));
    const dmarc = out.find((i) => i.code === 'EMAIL_DMARC_FAIL')!;
    expect(dmarc).toMatchObject({ severity: 'high', title: 'DMARC alignment failed' });
    expect(dmarc.description).toMatch(/Forwarding and mailing lists/);
    const reply = out.find((i) => i.code === 'EMAIL_REPLYTO_MISMATCH')!;
    expect(reply.title).toMatch(/free mailbox/);
    expect(reply.evidence).toContain('paypal.resolution.center@gmail.com');
    expect(codes(out)).toEqual(expect.arrayContaining(['EMAIL_SPF_FAIL', 'EMAIL_DKIM_NONE']));
    // From is the real paypal.com domain, so no display-name brand claim
    expect(codes(out)).not.toContain('EMAIL_DISPLAY_NAME_BRAND');
  });

  it('detects display-name address spoofing, Return-Path mismatch and time reversal', () => {
    const out = heur(fixture('display-spoof.txt'));
    expect(out.find((i) => i.code === 'EMAIL_DISPLAY_NAME_SPOOF')?.severity).toBe('high');
    expect(out.find((i) => i.code === 'EMAIL_RETURNPATH_MISMATCH')?.severity).toBe('low');
    expect(codes(out)).toEqual(expect.arrayContaining(['EMAIL_SPF_SOFTFAIL', 'EMAIL_DKIM_FAIL', 'EMAIL_DMARC_NONE', 'EMAIL_RECEIVED_TIME_REVERSAL', 'EMAIL_MISSING_HEADERS']));
  });
});

describe('From / Reply-To / Return-Path mismatch detection', () => {
  const hdr = (from: string, extra: string, auth = 'mx.example; spf=pass smtp.mailfrom=a.example; dkim=pass header.d=a.example; dmarc=pass header.from=a.example') =>
    `Authentication-Results: ${auth}\nFrom: ${from}\n${extra}\nDate: Mon, 2 Mar 2026 10:00:00 +0000\nMessage-ID: <1@a.example>\nTo: x@corp.example`;

  it('does not flag Reply-To within the same organisation as a mismatch', () => {
    const out = heur(hdr('News <news@a.example>', 'Reply-To: support@help.a.example'));
    expect(codes(out)).not.toContain('EMAIL_REPLYTO_MISMATCH');
    expect(codes(out)).toContain('EMAIL_REPLYTO_DIFFERENT_MAILBOX');
  });

  it('flags Reply-To at another organisation as medium', () => {
    expect(heur(hdr('News <news@a.example>', 'Reply-To: replies@b.example')).find((i) => i.code === 'EMAIL_REPLYTO_MISMATCH')?.severity).toBe('medium');
  });

  it('treats a Return-Path mismatch as context when DMARC passes (ESP bounce domain)', () => {
    expect(heur(hdr('News <news@a.example>', 'Return-Path: <bounce@esp.example>')).find((i) => i.code === 'EMAIL_RETURNPATH_MISMATCH')?.severity).toBe('info');
  });

  it('flags a brand display name from a free-mail account as high', () => {
    const out = heur(hdr('"Microsoft Account Team" <msteam.alerts@gmail.com>', '', 'mx.example; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com'));
    expect(out.find((i) => i.code === 'EMAIL_DISPLAY_NAME_BRAND')).toMatchObject({ severity: 'high' });
  });

  it('does not flag a brand display name sent from the brand’s own domain', () => {
    expect(codes(heur(hdr('"Microsoft" <account@microsoft.com>', '')))).not.toContain('EMAIL_DISPLAY_NAME_BRAND');
  });

  it('notes missing authentication results without inventing a result', () => {
    const out = heur('From: a@b.example\nTo: c@d.example\nSubject: hi\nDate: Mon, 2 Mar 2026 10:00:00 +0000\nMessage-ID: <x@b.example>');
    expect(codes(out)).toEqual(['EMAIL_NO_AUTH_RESULTS', 'EMAIL_NO_RECEIVED']);
    expect(out.every((i) => i.severity === 'info')).toBe(true);
  });
});
