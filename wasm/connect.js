import init, { hashes } from "./pkg/wasm.js";

async function* lines(stream) {
  stream = stream.pipeThrough(new TextDecoderStream());
  const reader = stream.getReader();
  let buffer = "";
  let current;
  while ((current = await reader.read())) {
    if (current.done) {
      if (buffer) yield buffer;
      return;
    } else {
      for (let i = 0; i < current.value.length; i++) {
        if (current.value[i] == "\n") {
          yield buffer;
          buffer = "";
        } else {
          buffer += current.value[i];
        }
      }
    }
  }
}

window.connect = async function connect(host, port) {
  const url = new URL("https://x");
  url.hostname = host;
  url.port = port;
  await init();
  const serverCertificateHashes = hashes(
    url.hostname,
    BigInt(Math.floor(Date.now() / 1000)),
  ).map((value) => ({
    algorithm: "sha-256",
    value,
  }));
  let transport = new WebTransport(url, {
    serverCertificateHashes,
  });
  await transport.ready;
  /** @type {{value: WebTransportBidirectionalStream}} */
  const { value: stream } = await transport.incomingBidirectionalStreams
    .getReader()
    .read();
  const writer = stream.writable.getWriter();
  const encoder = new TextEncoder();
  return {
    lines: lines(stream.readable),
    send: (message) => {
      writer.write(encoder.encode(message));
    },
  };
};
