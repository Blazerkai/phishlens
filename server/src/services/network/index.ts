import type { NetworkConfig } from '../../config/index.js';
import type { EngineServices } from '../../analyzers/types.js';
import { createDnsService } from './dns.js';
import { createHttpService } from './http.js';
import { createTlsService } from './tls.js';

export function createNetworkServices(n: NetworkConfig): EngineServices {
  return {
    dns: createDnsService({ timeoutMs: n.dnsTimeoutMs, servers: n.dnsServers }),
    http: createHttpService({ allowedPorts: n.allowedPorts }),
    tls: createTlsService({ allowedPorts: n.allowedPorts }),
  };
}
