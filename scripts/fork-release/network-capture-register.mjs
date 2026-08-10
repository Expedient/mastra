import { appendFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

const capturePath = process.env.FORK_RELEASE_NETWORK_CAPTURE;
if (!capturePath) throw new Error('FORK_RELEASE_NETWORK_CAPTURE is required by the network capture preload');

function record(protocol, host, port, source) {
  const event = {
    protocol: String(protocol).replace(/:$/, '').toLowerCase(),
    host: String(host || 'localhost')
      .replace(/^\[|\]$/g, '')
      .toLowerCase(),
    port: Number(port),
    source,
  };
  appendFileSync(capturePath, `${JSON.stringify(event)}\n`);
}

function optionsDestination(defaultProtocol, defaultPort, input, options) {
  if (typeof input === 'string' || input instanceof URL) {
    const url = new URL(input);
    return { protocol: url.protocol, host: url.hostname, port: url.port || defaultPort };
  }
  const merged = { ...(input ?? {}), ...(options ?? {}) };
  return {
    protocol: merged.protocol ?? defaultProtocol,
    host: merged.hostname ?? merged.host ?? 'localhost',
    port: merged.port ?? defaultPort,
  };
}

function patchRequest(module, protocol, defaultPort) {
  const originalRequest = module.request.bind(module);
  const originalGet = module.get.bind(module);
  module.request = function capturedRequest(input, options, callback) {
    const destination = optionsDestination(protocol, defaultPort, input, options);
    record(destination.protocol, destination.host, destination.port, `${protocol.replace(':', '')}.request`);
    return originalRequest(input, options, callback);
  };
  module.get = function capturedGet(input, options, callback) {
    const destination = optionsDestination(protocol, defaultPort, input, options);
    record(destination.protocol, destination.host, destination.port, `${protocol.replace(':', '')}.get`);
    return originalGet(input, options, callback);
  };
}

patchRequest(http, 'http:', 80);
patchRequest(https, 'https:', 443);

const originalNetConnect = net.connect.bind(net);
net.connect = function capturedNetConnect(...args) {
  const normalized = net._normalizeArgs(args);
  const options = normalized[0] ?? {};
  if (!options.path) record('tcp', options.host ?? 'localhost', options.port, 'net.connect');
  return originalNetConnect(...args);
};
net.createConnection = net.connect;

const originalTlsConnect = tls.connect.bind(tls);
tls.connect = function capturedTlsConnect(...args) {
  const options = typeof args[0] === 'object' ? args[0] : { port: args[0], host: args[1] };
  record('tls', options.servername ?? options.host ?? 'localhost', options.port ?? 443, 'tls.connect');
  return originalTlsConnect(...args);
};

if (typeof globalThis.fetch === 'function') {
  const originalFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = function capturedFetch(input, init) {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    record(url.protocol, url.hostname, url.port || (url.protocol === 'https:' ? 443 : 80), 'fetch');
    return originalFetch(input, init);
  };
}
