# Secure payment with server identification using Elliptic protocol signature and key exchange,
# encryption-decryption with Blowfish checking with SHA-256.

import client
import server
import elliptic
import collections


def start():
    """
    This is the start point of our simulation.
    """
    # Define a Coordinate Tuple
    Coord = collections.namedtuple("Coord", ["x", "y"])

    # Initialize an elliptic curve
    big_prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    ec = elliptic.EC(0, 7, big_prime, Coord(Gx, Gy), order)

    # Initialize a server
    sv = server.Server(ec)

    # Initialize a client
    cl = client.Client(sv, ec)


start()
