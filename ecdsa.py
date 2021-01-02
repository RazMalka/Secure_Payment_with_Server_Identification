import binascii as bs
import random
import elliptic
import hashlib


class Ecdsa:
    @classmethod
    def sign(cls, ec, message, privateNumber):
        """
        This method signs messages through ECDSA Algorithm.
        """
        # Calculate  e = HASH(m). (Here HASH is a cryptographic hash function,
        # SHA-256, with the output converted to an integer)
        hashMessage_temp = cls.sha256(str(message))
        hashMessage = ''.join(str(w) for w in hashMessage_temp)

        # Convert string to HEXA representation
        z = cls.stringToNumber(hashMessage)

        r, s = 0, 0
        curvePoint = None
        while r == 0 or s == 0:
            # Select a cryptographically secure random integer k from  [1,n-1].
            k = random.randint(1, ec.order - 1)
            # Calculate the curve point (x1,y1) = k*G
            curvePoint = ec.mul(ec.G, k)
            # Calculate r = x1 mod n
            r = curvePoint.x % ec.order
            # Calculate s = k^{-1}*(z+rd) mod n
            s = ((z + r * privateNumber) *
                 (elliptic.inv(k, ec.order))) % ec.order
        # The signature is the pair (r,s) if r = 0 or s = 0 repeat the proccess
        signature = [r, s]
        return signature

    @classmethod
    def verify(cls, ec, message, signature, publicKey):
        """
        This method verifies messages through ECDSA Algorithm.
        """
        # Calculate  e = HASH(m), where HASH is the same function used in the signature generation.
        hashMessage_temp = cls.sha256(str(message))
        hashMessage = ''.join(str(w) for w in hashMessage_temp)

        # Convert string to HEXA representation
        z = cls.stringToNumber(hashMessage)

        sigR = signature[0]
        sigS = signature[1]
        # Calculate invert of s for later calculations
        inv = elliptic.inv(sigS, ec.order)
        # Calculate u1 = zs^{-1}mod n
        u1 = (z * inv) % ec.order
        # Calculate u2 = rs^{-1}mod n
        u2 = (sigR * inv) % ec.order
        # Calculate u1*G
        u1_res = ec.mul(ec.G, u1)
        # Calculate u2*Qa
        u2_res = ec.mul(publicKey, u2)
        # Calculate the curve point (x1,y1) = u1*G+ u2*Qa
        add = ec.add(u1_res, u2_res)
        # The signature is valid if r mod n = x_mod n, invalid otherwise.
        return sigR % ec.order == add.x % ec.order

    @classmethod
    def stringToNumber(cls, string):
        return int(bs.hexlify(str.encode(string)), 16)

    @classmethod
    def sha256(cls, input_string):
        return hashlib.sha256(str(input_string).encode('utf-8')).hexdigest()
