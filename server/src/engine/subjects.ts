/** Canonical evidence-graph node keys, shared by analyzers and the graph builder. */
export const subject = {
  url: (normalized: string) => `url:${normalized}`,
  host: (hostname: string) => `host:${hostname.toLowerCase()}`,
  domain: (registrable: string) => `domain:${registrable.toLowerCase()}`,
  ip: (ip: string) => `ip:${ip}`,
  certificate: (host: string, port: number) => `cert:${host.toLowerCase()}:${port}`,
  dns: (name: string) => `dns:${name.toLowerCase()}`,
  rdap: (domain: string) => `rdap:${domain.toLowerCase()}`,
  redirect: (startUrl: string, hop: number) => `redirect:${startUrl}#${hop}`,
  address: (addr: string) => `address:${addr.toLowerCase()}`,
  email: () => 'email:headers',
  mailserver: (index: number) => `mailserver:${index}`,
  message: () => 'message',
  root: () => 'investigation',
};
