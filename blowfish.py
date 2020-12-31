import blowfish_const as const


class Blowfish():
    def __init__(self, key):
        """
        Initialize new pbox and sbox for blowfish instance,
        and calls initialize for pbox.
        """
        self.p_new = const.p.copy()  # p[i] is initialized with pi() values
        self.p = const.p.copy()
        self.s = const.s.copy()
        self.initialize(key)

    def swap(self, a, b):
        """
        Swap between a and b.
        """
        temp = a
        a = b
        b = temp
        return a, b

    @staticmethod
    def generate_input_key(key):
        """
        Generates a correctly formatted list of hexadecimal values from input key.
        """
        if (len(hex(key)) > 8 * 14):
            print("Key Too Long!")
            exit(1)

        key = hex(key)[2:]
        padding = (8 * 14) - len(key)
        key = "0" * padding + key  # add pading to the key
        n = 8
        res = [int(key[i:i+n], 16) for i in range(0, len(key), n)]
        key = res

        return key

    def initialize(self, key):
        """
        Initialize p-box using xor with 18 subkeys.
        This function initializes the pbox with xor between it with input key.
        The p[i] array is already initialized with pi() numbers
        The new p[i] gets the value of oldP[i] xor key[i]
        """
        for i in range(0, 18):
            self.p[i] = self.p[i] ^ key[i % 14]
        k = 0
        data = 0
        for i in range(0, 9):
            temp = self.encryption(data)
            self.p[k] = temp >> 32
            k += 1
            self.p[k] = temp & 0xffffffff
            k += 1
            data = temp

    def encryption(self, data):
        """
        This function performs encryption of data with blowfish.

        """
        L = data >> 32  # get the left 32 bit
        R = data & 0xffffffff  # get the right 32 bit
        for i in range(0, 16):
            L = self.p[i] ^ L  # xor with the p[i]
            L1 = self.F(L)
            R = R ^ self.F(L1)
            L, R = self.swap(L, R)
        L, R = self.swap(L, R)
        L = L ^ self.p[17]
        R = R ^ self.p[16]
        encrypted = (L << 32) ^ R
        return encrypted

    def F(self, L):
        """
        The F-function splits the 32-bit input into four eight-bit quarters,
        and uses the quarters as input to the S-boxes.
        The S-boxes accept 8-bit input and produce 32-bit output.
        The outputs are added modulo 2^32 and XORed to produce the final 32-bit output.
        """
        temp = self.s[0][L >> 24]
        temp = (temp + self.s[1][L >> 16 & 0xff]) % 2**32
        temp = temp ^ self.s[2][L >> 8 & 0xff]
        temp = (temp + self.s[3][L & 0xff]) % 2**32
        return temp

    def decryption(self, data):
        """
        This function performs decryption of data with blowfish.
        The reverse of the encryption
        """
        L = data >> 32  # get the left 32 bit
        R = data & 0xffffffff  # get the right 32 bit
        for i in range(17, 1, -1):
            L = self.p[i] ^ L
            L1 = self.F(L)
            R = R ^ self.F(L1)
            L, R = self.swap(L, R)
        L, R = self.swap(L, R)
        L = L ^ self.p[0]
        R = R ^ self.p[1]
        decrypted_data1 = (L << 32) ^ R
        return decrypted_data1
