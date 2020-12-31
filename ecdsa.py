import binascii as bs
import sha256
import random
import elliptic


class Ecdsa:
    @classmethod
    def sign(cls, ec, message, privateNumber):
        """
        This method signs messages through ECDSA Algorithm.
        """
        hashMessage_temp = sha256.sha_256(str(message))
        hashMessage = ''.join(str(w) for w in hashMessage_temp)
        z = cls.stringToNumber(hashMessage)

        r, s = 0, 0
        curvePoint = None
        while r == 0 or s == 0:
            k = random.randint(1, ec.order - 1)
            curvePoint = ec.mul(ec.G, k)
            r = curvePoint.x % ec.order
            s = ((z + r * privateNumber) *
                 (elliptic.inv(k, ec.order))) % ec.order
        signature = [r, s]
        return signature

    @classmethod
    def verify(cls, ec, message, signature, publicKey):
        """
        This method verifies messages through ECDSA Algorithm.
        """
        hashMessage_temp = sha256.sha_256(str(message))
        hashMessage = ''.join(str(w) for w in hashMessage_temp)
        z = cls.stringToNumber(hashMessage)

        sigR = signature[0]
        sigS = signature[1]
        inv = elliptic.inv(sigS, ec.order)
        u1 = (z * inv) % ec.order
        u2 = (sigR * inv) % ec.order
        u1_res = ec.mul(ec.G, u1)
        u2_res = ec.mul(publicKey, u2)
        add = ec.add(u1_res, u2_res)
        return sigR % ec.order == add.x % ec.order

    @classmethod
    def stringToNumber(cls, string):
        return int(bs.hexlify(str.encode(string)), 16)
