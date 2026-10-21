// The Node check: Node's own TLS check with the root list compiled into node (its default), in memory
// (a duplex pair: no sockets, no ports). Run in ~/app with each Node build:
//
//   ./node-26.12.0 nodecheck.mjs     # before the fix
//   ./node-26.12.1 nodecheck.mjs     # the 21 October release (nodejs/node #66871)
//
// The other side presents the made-up leaf for api.example.com (server/chain.pem, signed with a throwaway key) and
// the real public intermediates. It prints the same lines as ./check:
//   trusted root: found, signature: made up   (CERT_SIGNATURE_FAILURE: a trusted root was found)
//   distrusted key                            (CERT_REVOKED: the key is on Node's block list)
//   no trusted root                           (any other verify error)
// followed by Node's own error code.
import fs from "node:fs";
import tls from "node:tls";
import { duplexPair } from "node:stream";

console.log(`node ${process.version}`);
const [a, b] = duplexPair();
const server = new tls.TLSSocket(a, { isServer: true, key: fs.readFileSync("server/leaf.key"), cert: fs.readFileSync("server/chain.pem") });
server.on("error", () => {});
const client = tls.connect({ socket: b, servername: "api.example.com" });
client.on("secureConnect", () => { console.log("trusted: the whole chain, signature included"); process.exit(0); });
client.on("error", (e) => {
  const line = e.code === "CERT_SIGNATURE_FAILURE" ? "trusted root: found, signature: made up"
    : e.code === "CERT_REVOKED" ? "distrusted key" : "no trusted root";
  console.log(line);
  console.log(`error: ${e.code}`);
  process.exit(0);
});
