/**
 * Reference lists used by deterministic heuristics.
 *
 * These are deliberately small, editable and documented. They are *context*,
 * not reputation data: membership in a list never makes something malicious on
 * its own, and every indicator derived from a list says so in its description.
 */
export interface ReferenceLists {
  /** Consumer mailbox providers: anyone can register an address here. */
  freemailDomains: string[];
  /** Link shorteners: hide the real destination until resolved. */
  urlShorteners: string[];
  /**
   * TLDs that appear disproportionately in abuse reporting. Review for your
   * environment — many legitimate sites use these. Contributes LOW severity only.
   */
  elevatedAbuseTlds: string[];
  /** Query parameter names commonly used to carry a redirect target. */
  redirectParams: string[];
  /** Shared hosting / user-content platforms (registrable domain belongs to the platform). */
  sharedHostingSuffixes: string[];
  /** Pattern → provider name for nameservers, MX hosts and CNAME targets. */
  providerPatterns: { pattern: RegExp; name: string; role: 'dns' | 'mail' | 'hosting' }[];
  /** TXT records that identify a hosting platform's custom-domain verification. */
  txtProviderPatterns: { pattern: RegExp; name: string }[];
}

export const defaultLists: ReferenceLists = {
  freemailDomains: [
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
    'aol.com', 'icloud.com', 'me.com', 'mail.com', 'gmx.com', 'gmx.net', 'proton.me', 'protonmail.com', 'zoho.com',
    'yandex.com', 'yandex.ru', 'mail.ru', 'qq.com', '163.com', 'tutanota.com', 'fastmail.com',
  ],
  urlShorteners: [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'rb.gy', 't.ly', 'tiny.cc', 's.id', 'lnkd.in', 'qrco.de',
  ],
  elevatedAbuseTlds: ['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'cfd', 'sbs', 'icu', 'buzz', 'cyou', 'lol'],
  redirectParams: [
    'url', 'u', 'redirect', 'redirect_uri', 'redirect_url', 'redir', 'return', 'returnto', 'return_to', 'returnurl',
    'next', 'dest', 'destination', 'goto', 'target', 'continue', 'forward', 'link', 'out', 'r',
  ],
  sharedHostingSuffixes: [
    'github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'herokuapp.com', 'azurewebsites.net', 'blob.core.windows.net', 'web.core.windows.net', 'appspot.com',
    'glitch.me', 'repl.co', 'onrender.com', 'weebly.com', 'wixsite.com', 'squarespace.com', 'webflow.io',
    'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'r2.dev', 'storage.googleapis.com', 's3.amazonaws.com',
    'sharepoint.com', 'godaddysites.com', 'blogspot.com', '000webhostapp.com', 'ipfs.io',
  ],
  providerPatterns: [
    { pattern: /\.ns\.cloudflare\.com$/i, name: 'Cloudflare DNS', role: 'dns' },
    { pattern: /\.awsdns-\d+\.(com|net|org|co\.uk)$/i, name: 'Amazon Route 53', role: 'dns' },
    { pattern: /\.azure-dns\.(com|net|org|info)$/i, name: 'Azure DNS', role: 'dns' },
    { pattern: /^ns\d*\.google\.com$|\.googledomains\.com$/i, name: 'Google DNS hosting', role: 'dns' },
    { pattern: /\.domaincontrol\.com$/i, name: 'GoDaddy DNS', role: 'dns' },
    { pattern: /\.registrar-servers\.com$/i, name: 'Namecheap DNS', role: 'dns' },
    { pattern: /\.nsone\.net$/i, name: 'NS1', role: 'dns' },
    { pattern: /\.dynect\.net$|\.ultradns\.(com|net|org|biz|info)$/i, name: 'Vercara / Oracle Dyn', role: 'dns' },
    { pattern: /\.akam\.net$|\.akamaiedge\.net$/i, name: 'Akamai', role: 'dns' },
    { pattern: /\.digitalocean\.com$/i, name: 'DigitalOcean DNS', role: 'dns' },
    { pattern: /\.hostinger\.com$|\.dns-parking\.com$/i, name: 'Hostinger DNS', role: 'dns' },
    { pattern: /\.(google|googlemail)\.com$/i, name: 'Google Workspace / Gmail', role: 'mail' },
    { pattern: /\.mail\.protection\.outlook\.com$/i, name: 'Microsoft 365 (Exchange Online)', role: 'mail' },
    { pattern: /\.pphosted\.com$/i, name: 'Proofpoint', role: 'mail' },
    { pattern: /\.mimecast\.com$/i, name: 'Mimecast', role: 'mail' },
    { pattern: /\.messagelabs\.com$/i, name: 'Broadcom Email Security.cloud', role: 'mail' },
    { pattern: /\.zoho\.(com|eu|in)$/i, name: 'Zoho Mail', role: 'mail' },
    { pattern: /\.yahoodns\.net$/i, name: 'Yahoo Mail', role: 'mail' },
    { pattern: /\.amazonses\.com$|\.amazonaws\.com$/i, name: 'Amazon SES / AWS', role: 'mail' },
    { pattern: /\.mailgun\.org$/i, name: 'Mailgun', role: 'mail' },
    { pattern: /\.sendgrid\.net$/i, name: 'SendGrid', role: 'mail' },
    { pattern: /\.cloudfront\.net$/i, name: 'Amazon CloudFront', role: 'hosting' },
    { pattern: /\.azurewebsites\.net$|\.azureedge\.net$|\.trafficmanager\.net$/i, name: 'Microsoft Azure', role: 'hosting' },
    { pattern: /\.herokuapp\.com$|\.herokudns\.com$/i, name: 'Heroku', role: 'hosting' },
    { pattern: /\.github\.io$/i, name: 'GitHub Pages', role: 'hosting' },
    { pattern: /\.netlify\.(app|com)$/i, name: 'Netlify', role: 'hosting' },
    { pattern: /\.vercel-dns\.com$|\.vercel\.app$/i, name: 'Vercel', role: 'hosting' },
    { pattern: /\.fastly\.net$|\.fastlylb\.net$/i, name: 'Fastly', role: 'hosting' },
    { pattern: /\.edgekey\.net$|\.akamaized\.net$/i, name: 'Akamai', role: 'hosting' },
    { pattern: /\.wixdns\.net$/i, name: 'Wix', role: 'hosting' },
    { pattern: /\.shopify\.com$|\.myshopify\.com$/i, name: 'Shopify', role: 'hosting' },
    { pattern: /\.squarespace\.com$/i, name: 'Squarespace', role: 'hosting' },
    { pattern: /\.compute\.amazonaws\.com$/i, name: 'Amazon EC2', role: 'hosting' },
    { pattern: /\.bc\.googleusercontent\.com$/i, name: 'Google Cloud', role: 'hosting' },
    { pattern: /\.linodeusercontent\.com$|\.members\.linode\.com$/i, name: 'Akamai Linode', role: 'hosting' },
    { pattern: /\.vultrusercontent\.com$/i, name: 'Vultr', role: 'hosting' },
    { pattern: /\.your-server\.de$/i, name: 'Hetzner', role: 'hosting' },
    { pattern: /\.ovh\.net$|\.ip-\d+-\d+-\d+\.(eu|net|us)$/i, name: 'OVHcloud', role: 'hosting' },
  ],
  txtProviderPatterns: [
    { pattern: /^hosting-site=/i, name: 'Firebase Hosting' },
    { pattern: /^vercel-domain-verification=|^_vercel/i, name: 'Vercel' },
    { pattern: /^netlify-verification=/i, name: 'Netlify' },
  ],
};
