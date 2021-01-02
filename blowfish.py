import blowfish_const as const


class Blowfish():
    def __init__(self, key):
        """
        Initialize new p-array and sbox for blowfish instance,
        and calls initialize for p-array.
        """
        # p[i] is initialized with pi values
        self.p_new = const.p.copy()
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

    # TODO add example
    @staticmethod
    def generate_input_key(key):
        """
        Generates a correctly formatted list of hexadecimal values from input key.
        """
        # Check if the input key is of valid length
        if (len(hex(key)) > 8 * 14):
            print("Key Too Long!")
            exit(1)

        # Remove '\x' from beginning of string
        key = hex(key)[2:]
        # Padding the input string
        padding = (8 * 14) - len(key)
        key = "0" * padding + key
        # n sets the length of each substring in the division
        n = 8
        # Generate a correctly formatted list of hex values from input key
        res = [int(key[i:i+n], 16) for i in range(0, len(key), n)]
        key = res

        return key

    def initialize(self, key):
        """
        Initialize p-array using xor with 18 subkeys.
        This function initializes the p-array with xor between it with input key.
        The p[i] array is already initialized with pi() numbers
        The new p[i] gets the value of oldP[i] xor key[i]
        """
        # Xor between the subkeys of p-array and the input key
        for i in range(0, 18):
            self.p[i] = self.p[i] ^ key[i % 14]

    def encryption(self, data):
        """
        This function performs encryption of data with blowfish.
        """
        # Encryption algorithm implemented from pseudo-code
        # As described in Bruce Schneier's Workshop Article:
        # https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html
        L = data >> 32              # get the left 32 bit
        R = data & 0xffffffff       # get the right 32 bit
        # Divide x into two 32-bit halves: xL, xR
        for i in range(0, 16):
            L = self.p[i] ^ L       # xor with the p[i]
            R = R ^ self.F(L)
            # Swap xL and xR
            L, R = self.swap(L, R)
        # Swap xL and xR (Undo the last swap.)
        L, R = self.swap(L, R)
        # Post-Processing
        L = L ^ self.p[17]
        R = R ^ self.p[16]
        # Recombine xL and xR
        encrypted = (L << 32) ^ R
        return encrypted

    def decryption(self, data):
        """
        This function performs decryption of data with blowfish.
        It reverses the encryption.
        """
        # Decryption is exactly the same as encryption,
        # except that P1, P2,…, P18 are used in the reverse order.
        # Decryption algorithm implemented from pseudo-code
        # As described in Bruce Schneier's Workshop Article:
        # https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html
        L = data >> 32              # get the left 32 bit
        R = data & 0xffffffff       # get the right 32 bit
        # Divide x into two 32-bit halves: xL, xR
        for i in range(17, 1, -1):
            L = self.p[i] ^ L       # xor with the p[i]
            R = R ^ self.F(L)
            # Swap xL and xR
            L, R = self.swap(L, R)
        # Swap xL and xR (Undo the last swap.)
        L, R = self.swap(L, R)
        # Post-Processing
        L = L ^ self.p[0]
        R = R ^ self.p[1]
        # Recombine xL and xR
        decrypted_data1 = (L << 32) ^ R
        return decrypted_data1

    def F(self, L):
        """
        The F-function splits the 32-bit input into four eight-bit quarters,
        and uses the quarters as input to the S-boxes.
        The S-boxes accept 8-bit input and produce 32-bit output.
        The outputs are added modulo 2^32 and XORed to produce the final 32-bit output.
        """
        # Divide xL into four eight-bit quarters: a, b, c, and d
        # F(xL) = ((S1,a + S2,b mod 2^32) XOR S3,c) + S4,d mod 2^32
        temp = self.s[0][L >> 24]
        temp = (temp + self.s[1][L >> 16 & 0xff]) % 2**32
        temp = temp ^ self.s[2][L >> 8 & 0xff]
        temp = (temp + self.s[3][L & 0xff]) % 2**32
        return temp
