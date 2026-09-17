# Reachline

Reachline is a small, stateless connectivity diagnostic UI. It accepts hostnames, IP addresses, URLs, explicit ports, and UNC/SMB-style network paths. It deliberately avoids a ping-only verdict: DNS, TCP, and HTTP signals are interpreted separately so that an ICMP block or silent firewall does not become a false “machine down” result.

## Run locally

Requires Node.js 22 and npm.

```bash
npm ci
npm run build
npm start
```

Open `http://localhost:8080`. For the containerized path, run `docker compose up --build`.

## Interpreting results

- **Reachable** means at least one tested service accepted a TCP connection or an HTTP endpoint responded.
- **Inconclusive** means the name resolved but tested services refused, timed out, or were filtered. A refusal is shown as evidence that something answered, but is not promoted to confirmed service reachability.
- **Not resolved** means DNS/name resolution failed from the Reachline server.

Checks originate from the deployed server's network, not the user's browser. Results can differ across VLANs, VPNs, proxies, security groups, and split-horizon DNS.

## Operational note

This app intentionally performs outbound probes chosen by its users. It includes validation, a small per-process request limit, bounded timeouts, and no stored history. If exposed outside a trusted network, add an upstream network policy and rate limiter appropriate to the environment, even when product-level authentication is not desired.
