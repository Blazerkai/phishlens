import type { Brand } from '@phishlens/shared';
import { defaultLists } from '../src/config/lists.js';

export const lists = defaultLists;

let nextId = 1;
export function brand(name: string, keywords: string[], officialDomains: string[]): Brand {
  return { id: nextId++, name, keywords, officialDomains, createdAt: '2026-01-01T00:00:00.000Z' };
}

export const brands: Brand[] = [
  brand('PayPal', ['paypal'], ['paypal.com', 'paypal.me']),
  brand('Microsoft', ['microsoft', 'office365', 'outlook'], ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'microsoftonline.com']),
  brand('Google', ['google', 'gmail'], ['google.com', 'gmail.com']),
  brand('DHL', ['dhl'], ['dhl.com']),
];

export const codes = (items: { code: string }[]) => items.map((i) => i.code);
