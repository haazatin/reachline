import assert from "node:assert/strict";
import test from "node:test";
import { parseTarget } from "../src/connectivity.js";

test("parses a hostname with the default layered ports", () => {
  const target = parseTarget("server.example.com");
  assert.equal(target.host, "server.example.com");
  assert.deepEqual(target.ports, [443, 80, 22, 445]);
  assert.equal(target.kind, "host");
});

test("parses URLs and preserves their path", () => {
  const target = parseTarget("https://example.com/status");
  assert.equal(target.host, "example.com");
  assert.equal(target.path, "/status");
  assert.deepEqual(target.ports, [443]);
  assert.equal(target.url, "https://example.com/status");
});

test("parses explicit IPv4 and IPv6 ports", () => {
  assert.deepEqual(parseTarget("10.0.0.8:8443").ports, [8443]);
  const ipv6 = parseTarget("[2001:db8::1]:443");
  assert.equal(ipv6.host, "2001:db8::1");
  assert.deepEqual(ipv6.ports, [443]);
});

test("parses UNC paths as SMB targets", () => {
  const target = parseTarget("\\\\fileserver\\shared\\reports");
  assert.equal(target.host, "fileserver");
  assert.equal(target.path, "/shared/reports");
  assert.deepEqual(target.ports, [445]);
});

test("rejects embedded credentials and invalid inputs", () => {
  assert.throws(() => parseTarget("https://user:pass@example.com"), /Credentials/);
  assert.throws(() => parseTarget("not a host"), /spaces/);
  assert.throws(() => parseTarget("tcp://example.com"), /must include a port/);
  assert.throws(() => parseTarget("example.com:70000"), /Port must be/);
});
