#!/usr/bin/env python3
"""The Python check: Python's own TLS check (the ssl module) against one root list, in memory (no
sockets, no ports). Run in ~/app:

    python3 pycheck.py certifi-2026.7.22.pem     # July's root list (has emSign ECC Root CA - G3)
    python3 pycheck.py certifi-2026.10.19.pem    # the fixed one

The other side presents the made-up leaf for api.example.com (server/chain.pem, signed with a throwaway key, so
its signature can't verify) and the real public intermediates. Reaching the signature means a trusted root was
found; it prints the same lines as ./check:
    trusted root: found, signature: made up    (exposed: this root list trusts the broken key)
    no trusted root                            (protected)
followed by OpenSSL's own error.
"""
import ssl
import sys

roots = sys.argv[1]
n = open(roots).read().count("BEGIN CERTIFICATE")
print(f"root list: {roots}, {n} roots")
server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain("server/chain.pem", "server/leaf.key")
client_ctx = ssl.create_default_context(cafile=roots)
c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
client = client_ctx.wrap_bio(c_in, c_out, server_hostname="api.example.com")
server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
for _ in range(20):
    for side in (client, server):
        try:
            side.do_handshake()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLCertVerificationError as e:
            if "signature failure" in e.verify_message:
                print("trusted root: found, signature: made up")
            else:
                print("no trusted root")
            print(f"error: {e.verify_message}")
            sys.exit(0)
        except ssl.SSLError:
            pass
    s_in.write(c_out.read())
    c_in.write(s_out.read())
print("trusted: the whole chain, signature included")
