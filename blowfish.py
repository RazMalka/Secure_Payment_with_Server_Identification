import blowfish_const as const

class Blowfish():
    def __init__(self, key):
        self.p_new = const.p.copy()
        self.p = const.p.copy()
        self.s = const.s.copy()
        self.initialize(key)

    def swap(self, a,b):
        temp = a
        a = b
        b = temp
        return a,b

    def initialize(self, key):
            for i in range(0,18):
                    self.p[i] = self.p[i]^key[i%14]
            k = 0
            data = 0
            for i in range(0,9):
                temp = self.encryption(data)
                self.p[k] = temp >> 32
                k+=1
                self.p[k] = temp & 0xffffffff
                k+=1
                data = temp

    def encryption(self, data):
            L = data>>32
            R = data & 0xffffffff
            for i in range(0,16):
                    L = self.p[i]^L
                    L1 = self.func(L)
                    R = R^self.func(L1)
                    L,R = self.swap(L,R)
            L,R = self.swap(L,R)
            L = L^self.p[17]
            R = R^self.p[16]
            encrypted = (L<<32) ^ R
            return encrypted

    def func(self, L):
        temp = self.s[0][L >> 24]
        temp = (temp + self.s[1][L >> 16 & 0xff]) % 2**32
        temp = temp ^ self.s[2][L >> 8 & 0xff]
        temp = (temp + self.s[3][L & 0xff]) % 2**32
        return temp

    def decryption(self, data):
        L = data >> 32
        R = data & 0xffffffff
        for i in range(17, 1, -1):
            L = self.p[i]^L
            L1 = self.func(L)
            R = R^self.func(L1)
            L,R = self.swap(L,R)
        L,R = self.swap(L,R)
        L = L^self.p[0]
        R = R^self.p[1]
        decrypted_data1 = (L<<32) ^ R
        return decrypted_data1