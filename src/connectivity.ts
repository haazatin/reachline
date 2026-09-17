import dns from "node:dns/promises";
import net from "node:net";
import { randomUUID } from "node:crypto";

export type ParsedTarget = {
  original: string;
  host: string;
  displayHost: string;
  ports: number[];
  url?: string;
  path?: string;
  kind: "url" | "host" | "ip" | "network-path";
};

export type ProbeStep = {
  label: string;
  status: "success" | "warning" | "failure" | "info";
  detail: string;
  durationMs?: number;
};

export type CheckResult = {
  id: string;
  target: { host: string; kind: ParsedTarget["kind"]; path?: string; ports: number[] };
  verdict: "reachable" | "inconclusive" | "not-resolved";
  summary: string;
  steps: ProbeStep[];
  checkedAt: string;
  durationMs: number;
};

const COMMON_PORTS = [443, 80, 22, 445];

export function parseTarget(value: string): ParsedTarget {
  const original = value.trim();
  if (!original) throw new Error("Enter a hostname, IP address, URL, or network path.");
  if (original.length > 512) throw new Error("Target must be 512 characters or fewer.");
  if (/\s/.test(original)) throw new Error("Targets cannot contain spaces.");

  const unc = original.match(/^\\\\([^\\/]+)(?:[\\/](.*))?$/);
  if (unc?.[1]) {
    return {
      original,
      host: unc[1],
      displayHost: unc[1],
      ports: [445],
      path: unc[2] ? `/${unc[2].replaceAll("\\", "/")}` : undefined,
      kind: "network-path",
    };
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(original)) {
    let parsed: URL;
    try {
      parsed = new URL(original);
    } catch {
      throw new Error("That URL or service path is not valid.");
    }
    if (parsed.username || parsed.password) throw new Error("Credentials are not allowed in targets.");
    const protocol = parsed.protocol.toLowerCase();
    if (!["http:", "https:", "tcp:", "smb:"].includes(protocol)) {
      throw new Error("Supported schemes are http, https, tcp, and smb.");
    }
    const defaultPort = protocol === "https:" ? 443 : protocol === "http:" ? 80 : protocol === "smb:" ? 445 : undefined;
    const port = parsed.port ? Number(parsed.port) : defaultPort;
    if (!port) throw new Error("A tcp:// target must include a port.");
    return {
      original,
      host: parsed.hostname,
      displayHost: parsed.hostname,
      ports: [port],
      url: protocol === "http:" || protocol === "https:" ? parsed.toString() : undefined,
      path: parsed.pathname === "/" ? undefined : parsed.pathname,
      kind: protocol === "smb:" ? "network-path" : "url",
    };
  }

  let hostPart = original;
  let path: string | undefined;
  const slashAt = original.search(/[\\/]/);
  if (slashAt > -1) {
    hostPart = original.slice(0, slashAt);
    path = `/${original.slice(slashAt + 1).replaceAll("\\", "/")}`;
  }

  let host = hostPart;
  let ports = path ? [443, 80, 445] : COMMON_PORTS;
  const bracketed = hostPart.match(/^\[([^\]]+)](?::(\d+))?$/);
  if (bracketed?.[1]) {
    host = bracketed[1];
    if (bracketed[2]) ports = [validatePort(bracketed[2])];
  } else if (net.isIP(hostPart) !== 6) {
    const hostPort = hostPart.match(/^([^:]+):(\d+)$/);
    if (hostPort?.[1] && hostPort[2]) {
      host = hostPort[1];
      ports = [validatePort(hostPort[2])];
    }
  }

  if (!host || (!net.isIP(host) && !isValidHostname(host))) {
    throw new Error("Enter a valid hostname, IPv4 address, IPv6 address, or URL.");
  }
  return {
    original,
    host,
    displayHost: host,
    ports,
    path,
    kind: net.isIP(host) ? "ip" : path ? "network-path" : "host",
  };
}

function validatePort(value: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be between 1 and 65535.");
  return port;
}

function isValidHostname(host: string): boolean {
  if (host.length > 253 || host === "localhost") return host === "localhost";
  return host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

type TcpOutcome = { port: number; state: "open" | "refused" | "filtered" | "error"; durationMs: number; code?: string };

function probeTcp(host: string, port: number, timeoutMs = 2200): Promise<TcpOutcome> {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (outcome: Omit<TcpOutcome, "port" | "durationMs">) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, durationMs: Date.now() - started, ...outcome });
    };
    socket.setTimeout(timeoutMs, () => finish({ state: "filtered", code: "TIMEOUT" }));
    socket.once("connect", () => finish({ state: "open" }));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED") finish({ state: "refused", code: error.code });
      else if (["ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH"].includes(error.code ?? "")) finish({ state: "filtered", code: error.code });
      else finish({ state: "error", code: error.code ?? "UNKNOWN" });
    });
  });
}

export async function checkConnectivity(target: ParsedTarget): Promise<CheckResult> {
  const started = Date.now();
  const steps: ProbeStep[] = [];
  let addresses: Array<{ address: string; family: number }> = [];

  const dnsStarted = Date.now();
  try {
    addresses = await withTimeout(dns.lookup(target.host, { all: true, verbatim: true }), 2500, "DNS lookup");
    const unique = [...new Set(addresses.map((item) => item.address))];
    steps.push({ label: "Name resolution", status: "success", detail: unique.join(", "), durationMs: Date.now() - dnsStarted });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Name resolution failed";
    steps.push({ label: "Name resolution", status: "failure", detail, durationMs: Date.now() - dnsStarted });
    return {
      id: randomUUID(),
      target: { host: target.displayHost, kind: target.kind, path: target.path, ports: target.ports },
      verdict: "not-resolved",
      summary: "The target name could not be resolved. Check spelling, DNS, VPN, and search-domain settings.",
      steps,
      checkedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
    };
  }

  const tcpResults = await Promise.all(target.ports.map((port) => probeTcp(target.host, port)));
  for (const result of tcpResults) {
    const description = result.state === "open"
      ? `TCP ${result.port} accepted a connection.`
      : result.state === "refused"
        ? `TCP ${result.port} actively refused the connection; the host or a firewall answered.`
        : result.state === "filtered"
          ? `TCP ${result.port} produced no usable response (${result.code ?? "timeout"}).`
          : `TCP ${result.port} failed (${result.code ?? "unknown error"}).`;
    steps.push({
      label: `TCP port ${result.port}`,
      status: result.state === "open" ? "success" : result.state === "refused" ? "warning" : "info",
      detail: description,
      durationMs: result.durationMs,
    });
  }

  let httpResponded = false;
  if (target.url) {
    const httpStarted = Date.now();
    try {
      const response = await fetch(target.url, {
        method: "HEAD",
        redirect: "follow",
        signal: AbortSignal.timeout(4500),
        headers: { "user-agent": "Reachline/1.0 connectivity-check" },
      });
      httpResponded = true;
      steps.push({
        label: "Application response",
        status: "success",
        detail: `HTTP ${response.status} responded at ${new URL(response.url).host}. Any HTTP status confirms application-layer reachability.`,
        durationMs: Date.now() - httpStarted,
      });
    } catch (error) {
      steps.push({
        label: "Application response",
        status: "warning",
        detail: error instanceof Error ? error.message : "The HTTP probe failed.",
        durationMs: Date.now() - httpStarted,
      });
    }
  }

  const hasOpen = tcpResults.some((result) => result.state === "open") || httpResponded;
  const hasRefused = tcpResults.some((result) => result.state === "refused");
  const verdict = hasOpen ? "reachable" : "inconclusive";
  const summary = hasOpen
    ? "The target is reachable from this app's network location."
    : hasRefused
      ? "The target answered, but none of the tested services accepted a connection. It may be reachable with those services closed or screened."
      : "No tested service answered. This does not prove the machine is down—firewalls, routing, VPNs, and blocked probes can look identical.";

  return {
    id: randomUUID(),
    target: { host: target.displayHost, kind: target.kind, path: target.path, ports: target.ports },
    verdict,
    summary,
    steps,
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
  };
}
