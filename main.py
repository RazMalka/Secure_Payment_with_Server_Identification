import sha256
import elliptic
import blowfish

# Order (?):
# INPUT -> HASH -> ENCRYPT -> SEND TO PAYMENT AUTHENTICATION SERVER -> DECRYPT -> COMPARE SHA-256 VALUES

# TITLE:
# Secure payment with server identification
# using Elliptic protocol signature and key exchange,
# encryption-decryption with SHARK checking with SHA-256.
from operator import xor
from os import urandom

# server identification
def payment(id, credit):
    bf = blowfish.Cipher(b"somekey")

    #data = urandom(10 * 8 + 2) # data to encrypt
    data = int(''.join(format(ord(x), 'b') for x in "banana"))

    # increment by one counters
    nonce = int.from_bytes(urandom(8), "big")
    enc_counter = blowfish.ctr_counter(nonce, f = xor)
    dec_counter = blowfish.ctr_counter(nonce, f = xor)

    data_encrypted = b"".join(bf.encrypt_ctr(data, enc_counter))
    data_decrypted = b"".join(bf.decrypt_ctr(data_encrypted, dec_counter))
    print("data_encrypted\n", data_encrypted)
    print("data_decrypted\n", data_decrypted)

    assert data == data_decrypted

    # SHA256 HASHING
    #print(sha256.sha_256(credit))
    # ELLIPTIC CURVE
    #a, b, q = 1, 18, 19
    #ec = elliptic.EC(a, b, q)

    #for i in range(19):
    #    try:
    #        g, _g = ec.at(i)
    #        print(g, _g)
    #    except:
    #        #print("No solution for", i ,"on curve. Please select another x-point.")
    #        pass
    #-----------
    #g, _g = ec.at(8)
    #original_g = g
    #for i in range(q - 1):
    #    g = elliptic.EC.mul(ec, g, i + 1)
    #    print(g)
    #    g = original_g
    #-----------


def main():
    payment("319151213", "4580120779488793")

main()