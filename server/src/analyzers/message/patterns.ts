import type { Severity } from '@phishlens/shared';

/**
 * Social-engineering patterns.
 *
 * Each pattern is a phrase-level construct (an action combined with an object,
 * or a deadline combined with a consequence), not a single keyword: "password"
 * alone matches nothing, "verify your password within 24 hours" does.
 *
 * Individual patterns carry low-to-medium weight. What makes a message look like
 * phishing is the combination of techniques, which the analyzer scores
 * separately (MESSAGE_SE_COMBINATION) and the correlation stage links to links,
 * sender identity and infrastructure.
 */
export type TechniqueCategory =
  | 'urgency'
  | 'threat'
  | 'credential_request'
  | 'payment_request'
  | 'secrecy'
  | 'impersonation'
  | 'reward'
  | 'document_lure'
  | 'generic_greeting';

export interface MessagePattern {
  id: string;
  category: TechniqueCategory;
  title: string;
  reason: string;
  severity: Severity;
  confidence: number;
  re: RegExp;
}

const ACTION = String.raw`(?:verify|confirm|update|validate|re-?enter|enter|provide|submit|reset|sign[- ]?in|log[- ]?in|re-?activate|unlock|restore)`;
const CREDENTIAL = String.raw`(?:password|passcode|pass code|credentials?|login (?:details|information|info)|account (?:details|information|info)|user ?name|pin(?: code)?|security (?:questions?|code)|one[- ]time (?:code|password)|otp|2fa code|mfa code|verification code|social security number|ssn|card (?:number|details)|cvv)`;
const DEADLINE = String.raw`(?:within|in the next|in less than)\s+(?:\d{1,3}|one|two|three|twenty[- ]four|forty[- ]eight|seventy[- ]two)\s*(?:hours?|hrs?|minutes?|mins?|days?)`;

export const MESSAGE_PATTERNS: MessagePattern[] = [
  // --- urgency -------------------------------------------------------------
  {
    id: 'URGENCY_DEADLINE',
    category: 'urgency',
    title: 'Urgency language detected',
    reason: 'The message sets a short deadline to create time pressure and discourage verification.',
    severity: 'low',
    confidence: 0.45,
    re: new RegExp(String.raw`\b${DEADLINE}\b`, 'i'),
  },
  {
    id: 'URGENCY_IMMEDIATE_ACTION',
    category: 'urgency',
    title: 'Urgency language detected',
    reason: 'The message demands immediate action, which discourages the reader from pausing to check the request.',
    severity: 'low',
    confidence: 0.45,
    re: new RegExp(String.raw`\b(?:immediate(?:ly)?|urgent(?:ly)?|as soon as possible|asap|right away|without delay|act now)\b[^.!?\n]{0,60}\b(?:${ACTION}|action|respond|reply|review|pay|click|sign)\b|\b(?:${ACTION}|respond|reply|pay|click)\b[^.!?\n]{0,40}\b(?:immediately|urgently|right away|without delay|today)\b`, 'i'),
  },
  {
    id: 'URGENCY_FINAL_NOTICE',
    category: 'urgency',
    title: 'Final-notice framing',
    reason: 'Labels such as "final notice" imply prior contact and an imminent consequence.',
    severity: 'low',
    confidence: 0.4,
    re: /\b(?:final|last) (?:notice|warning|reminder|attempt)\b/i,
  },
  // --- threat / consequence ---------------------------------------------------
  {
    id: 'THREAT_ACCOUNT_RESTRICTION',
    category: 'threat',
    title: 'Threat of account restriction',
    reason: 'The message claims an account or service is, or will be, suspended, locked or closed — a lever to make the reader comply quickly.',
    severity: 'medium',
    confidence: 0.45,
    re: /\b(?:account|access|mailbox|e-?mail|service|card|subscription|membership)\b[^.!?\n]{0,50}\b(?:(?:has been|have been|was|is|will be|being)\s+)?(?:suspended|locked|limited|restricted|disabled|closed|terminated|deactivated|blocked|put on hold|deleted)\b/i,
  },
  {
    id: 'THREAT_LEGAL',
    category: 'threat',
    title: 'Threat of legal or financial penalty',
    reason: 'Invoking legal action, police or penalties pressures the reader through fear.',
    severity: 'medium',
    confidence: 0.45,
    re: /\b(?:legal action|law enforcement|lawsuit|court|arrest warrant|penalt(?:y|ies)|late fee|collections? agency)\b/i,
  },
  // --- credential request -------------------------------------------------
  {
    id: 'CREDENTIAL_REQUEST',
    category: 'credential_request',
    title: 'Request for credentials',
    reason: 'The message asks the reader to enter or confirm a password, code or account details. Legitimate services do not ask for these by email; password-reset mail that the reader requested is the main exception.',
    severity: 'medium',
    confidence: 0.55,
    re: new RegExp(String.raw`\b${ACTION}\b[^.!?\n]{0,50}\b${CREDENTIAL}\b|\b${CREDENTIAL}\b[^.!?\n]{0,30}\b(?:expir\w*|will be (?:reset|deactivated|disabled))`, 'i'),
  },
  {
    id: 'CREDENTIAL_ACCOUNT_VERIFY',
    category: 'credential_request',
    title: 'Request to verify the account',
    reason: '"Verify your account" is a standard pretext for sending the reader to a sign-in page.',
    severity: 'low',
    confidence: 0.4,
    re: /\b(?:verify|confirm|validate|re-?activate|unlock|secure|restore)\s+(?:your|the)\s+(?:account|identity|mailbox|e-?mail|profile|access)\b/i,
  },
  // --- payment request ------------------------------------------------------
  {
    id: 'PAYMENT_GIFT_CARDS',
    category: 'payment_request',
    title: 'Request for gift cards',
    reason: 'Requests to buy gift cards and share their codes are a near-exclusive fraud pattern; no legitimate business or authority collects payment this way.',
    severity: 'high',
    confidence: 0.75,
    re: /\b(?:buy|purchase|get|send|pick up)\b[^.!?\n]{0,60}\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|apple cards?|amazon cards?)\b|\b(?:gift ?card)\b[^.!?\n]{0,60}\b(?:codes?|scratch|pins?)\b/i,
  },
  {
    id: 'PAYMENT_BANK_CHANGE',
    category: 'payment_request',
    title: 'Request to change bank or payment details',
    reason: 'Changing where money is sent is the core of invoice and payroll-diversion fraud. Such requests should be verified out-of-band.',
    severity: 'high',
    confidence: 0.65,
    re: /\b(?:update|change|new|updated)\b[^.!?\n]{0,30}\b(?:bank(?:ing)? (?:details|information|info|account)|payment (?:details|information|method|instructions)|direct deposit|remittance (?:details|information)|beneficiary)\b/i,
  },
  {
    id: 'PAYMENT_TRANSFER',
    category: 'payment_request',
    title: 'Request for payment or transfer',
    reason: 'The message asks the reader to pay or transfer money. Normal for real invoices; significant when combined with urgency, secrecy or a new payee.',
    severity: 'medium',
    confidence: 0.45,
    re: /\b(?:wire|bank) transfer\b|\b(?:pay|settle|remit|transfer|send)\b[^.!?\n]{0,40}\b(?:invoice|outstanding|balance|amount due|payment|the funds|\$\s?\d|€\s?\d|£\s?\d|\d+(?:[.,]\d{2})?\s?(?:usd|eur|gbp))\b/i,
  },
  {
    id: 'PAYMENT_CRYPTO',
    category: 'payment_request',
    title: 'Cryptocurrency payment referenced',
    reason: 'Cryptocurrency payments are irreversible and hard to trace, which is why extortion and fraud requests favour them.',
    severity: 'medium',
    confidence: 0.5,
    re: /\b(?:bitcoin|btc|usdt|tether|ethereum|crypto(?:currency)? wallet|wallet address)\b/i,
  },
  // --- secrecy / authority (BEC) ---------------------------------------------
  {
    id: 'SECRECY',
    category: 'secrecy',
    title: 'Request for secrecy',
    reason: 'Asking the reader not to tell anyone prevents the request from being checked — a hallmark of business email compromise.',
    severity: 'medium',
    confidence: 0.55,
    re: /\b(?:keep (?:this|it) (?:confidential|between us|quiet|private)|(?:don'?t|do not) (?:tell|discuss|mention|share this with|inform) (?:anyone|anybody|others|the team|your)|strictly confidential)\b/i,
  },
  {
    id: 'AUTHORITY_AVAILABILITY',
    category: 'secrecy',
    title: 'Executive availability check',
    reason: 'Openers like "are you at your desk?" are used to start a conversation before a payment or gift-card request.',
    severity: 'low',
    confidence: 0.4,
    re: /\b(?:are you (?:available|at your desk|around)|i need (?:you to|a) (?:quick )?favou?r|can you handle (?:a|this) (?:task|payment))\b/i,
  },
  // --- impersonation ----------------------------------------------------------
  {
    id: 'IMPERSONATION_DEPARTMENT',
    category: 'impersonation',
    title: 'Claims to be an internal department',
    reason: 'The message claims to come from IT, security, HR, payroll or support. That claim should match the sender’s actual domain.',
    severity: 'low',
    confidence: 0.35,
    re: /\b(?:(?:this is|from|regards,?|sincerely,?)\s+(?:the\s+)?(?:it|security|helpdesk|help desk|tech(?:nical)? support|support|billing|accounts?|payroll|hr|human resources|fraud|compliance|admin(?:istrator)?)\s+(?:department|team|desk|center|centre|services?))\b/i,
  },
  // --- reward ------------------------------------------------------------------
  {
    id: 'REWARD_LURE',
    category: 'reward',
    title: 'Unexpected reward or refund',
    reason: 'Unexpected prizes, refunds or unclaimed funds are offered to motivate the reader to provide details or pay a fee.',
    severity: 'medium',
    confidence: 0.45,
    re: /\b(?:you(?:'ve| have)? (?:won|been selected|been chosen)|claim your (?:prize|reward|refund|gift|funds)|unclaimed (?:funds|package|refund)|tax refund|lottery|inheritance)\b/i,
  },
  // --- document lure --------------------------------------------------------------
  {
    id: 'DOCUMENT_LURE',
    category: 'document_lure',
    title: 'Shared-document or message lure',
    reason: 'Notifications about a shared document, voicemail or secure message are a common way to send the reader to a fake sign-in page. Also common in legitimate collaboration mail.',
    severity: 'low',
    confidence: 0.3,
    re: /\b(?:shared (?:a |an )?(?:document|file|folder)|(?:view|open|review|access) (?:the |your )?(?:document|invoice|file|attachment|secure message|encrypted message)|new voicemail|missed (?:voice ?mail|fax)|e-?fax)\b/i,
  },
  // --- greeting ---------------------------------------------------------------------
  {
    id: 'GENERIC_GREETING',
    category: 'generic_greeting',
    title: 'Generic greeting',
    reason: 'A service you have an account with usually knows your name. Weak signal: many legitimate bulk messages also use generic greetings.',
    severity: 'low',
    confidence: 0.2,
    re: /^\s*(?:dear|hello|hi)\s+(?:valued\s+)?(?:customer|user|client|member|account ?holder|sir(?:\/madam)?|madam|e-?mail user|beneficiary)\b/im,
  },
];

/** Categories that represent pressure or asks; their co-occurrence is what matters. */
export const PRESSURE_CATEGORIES: TechniqueCategory[] = ['urgency', 'threat', 'credential_request', 'payment_request', 'secrecy', 'reward'];
