# Secure payment with server identification using Elliptic protocol signature and key exchange,
# encryption-decryption with Blowfish checking with SHA-256.

import client, server, elliptic, collections

def start():
    # Define a Coordinate Tuple
    Coord = collections.namedtuple("Coord", ["x", "y"])
    
    # Initialize an elliptic curve
    big_prime = 3546245297457217493590449191748546458005595187661976371
    ec = elliptic.EC(4, 16, big_prime, Coord(0, 4))

    # Initialize a server
    sv = server.Server(ec)

    # Initialize a client
    cl = client.Client(sv, ec)

start()