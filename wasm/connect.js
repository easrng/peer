import init, { hashes } from "./pkg/wasm.js";

window.connect = async function connect(host, port) {
  const url = new URL("https://x");
  url.hostname = host;
  url.port = port;
  await init();
  const serverCertificateHashes = hashes(
    url.hostname,
    BigInt(Math.floor(Date.now() / 1000))
  ).map((value) => ({
    algorithm: "sha-256",
    value,
  }));
  let transport = new WebTransport(url, {
    serverCertificateHashes,
  });
  await transport.ready;
  return transport;
};
