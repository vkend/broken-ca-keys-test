// Node's own TLS check, with the root list compiled into the node binary
// (its default), in memory: a duplex pair, no sockets, no ports.
//
//   node handshake.mjs <chain.pem> <leaf-key.pem>
//
// The server side presents the made-up leaf for api.example.com and the real
// public intermediates. The leaf's signature is made up, so the best a client
// can do is fail on it, which OpenSSL only reaches after finding a trusted
// root:
//   CERT_SIGNATURE_FAILURE                  -> a trusted root was found (exposed)
//   UNABLE_TO_GET_ISSUER_CERT_LOCALLY etc.  -> no trusted root (protected)
import fs from "node:fs";
import tls from "node:tls";
import { X509Certificate } from "node:crypto";
import { duplexPair } from "node:stream";

const [chain, key] = process.argv.slice(2);
const roots = tls.rootCertificates.map((p) => new X509Certificate(p));
const emsign = roots.find((c) => c.subject.includes("CN=emSign ECC Root CA - G3"));
console.log(`node ${process.version}: ${roots.length} roots compiled in; emSign ECC Root CA - G3 ${emsign ? "included" : "not included"}`);

const [a, b] = duplexPair();
const server = new tls.TLSSocket(a, { isServer: true, key: fs.readFileSync(key), cert: fs.readFileSync(chain) });
server.on("error", () => {});
const client = tls.connect({ socket: b, servername: "api.example.com" });   // default CA: the compiled-in list
client.on("secureConnect", () => { console.log("result: trusted"); process.exit(0); });
client.on("error", (e) => { console.log(`result: ${e.code}`); process.exit(0); });
