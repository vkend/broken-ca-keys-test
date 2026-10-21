#!/usr/bin/env python3
"""Python's own TLS check (the ssl module, OpenSSL) against a root list,
in memory: no sockets, no ports.

    handshake.py <root list.pem> <chain.pem> <leaf-key.pem>

The server side presents the made-up leaf for api.example.com and the real
public intermediates (EM DV TLS CA - G3B, emSign Root TLS CA - G3's
cross-sign by emSign ECC Root CA - G3). The leaf's signature is made up, so
the best a client can do is fail on it, which it only reaches once it has
found a trusted root:
  "certificate signature failure"   -> a trusted root was found (exposed)
  "unable to get local issuer ..."   -> no trusted root (protected)
"""
import ssl
import sys

roots, chain, key = sys.argv[1:4]
server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(chain, key)
client_ctx = ssl.create_default_context(cafile=roots)   # only this root list

c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
client = client_ctx.wrap_bio(c_in, c_out, server_hostname="api.example.com")
server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
print(f"Python {sys.version.split()[0]}, {ssl.OPENSSL_VERSION}")
for _ in range(20):
    for side in (client, server):
        try:
            side.do_handshake()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLCertVerificationError as e:
            print("result:", e.verify_message, f"(code {e.verify_code})")
            sys.exit(0)
        except ssl.SSLError:
            pass   # the server side sees the client's alert
    s_in.write(c_out.read())
    c_in.write(s_out.read())
print("result: trusted")
