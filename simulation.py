# Secure payment with server identification using Elliptic protocol signature and key exchange,
# encryption-decryption with Blowfish checking with SHA-256.

import client, server

def start():
    # Initialize a server
    sv = server.Server()

    # Initialize a client
    cl = client.Client(sv)

start()