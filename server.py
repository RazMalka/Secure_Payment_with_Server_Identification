
# This is a server

import blowfish
import random
import ecdsa


class Server():
    def __init__(self, ec):
        """
        This function is a constructor that initializes
        simulated variables username and hashed password.
        """
        self.ec = ec
        self.generate_private_key()
        self.simulation_username = "dima"
        self.simulation_hashed_password = "3ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"

    def generate_private_key(self):
        """
        This function generates a private key.
        """
        self.private_key_multiplier = random.randint(1, self.ec.q)
        self.private_key = self.ec.mul(self.ec.G, self.private_key_multiplier)

    def generate_public_key(self, key):
        """
        This function generates a public key.
        """
        self.Qa = key  # Qa is the public key used to verify signatures
        self.public_key = self.ec.mul(
            key, self.private_key_multiplier)  # k1 * k2 * G
        print("Generated Public Key:\t\t", self.public_key.x)
        print("\t\t\t\t", self.public_key.y)
        return self.private_key

    def validate_credentials(self, username, password):
        """
        This function validates credentials.
        For simulation purposes, it is for a predefined user "Dima",
        with password 1234 hashed with 256-sha algorithm.
        """
        return (username == self.simulation_username and password == self.simulation_hashed_password)

    def validate_blowfish_key_exchange(self, key_encrypted, signature):
        """
        This function validates the key exchange for blowfish.
        """
        result = ecdsa.Ecdsa.verify(self.ec, key_encrypted, signature, self.Qa)
        if (result is True):
            print(
                "Elliptic Curve Digital Signature Algorithm (ECDSA) Check Passed Successfully!")
        else:
            print(
                "Invalid Signature - Elliptic Curve Digital Signature Algorithm (ECDSA)")
            exit(1)

        bfkey_decryption_key = blowfish.Blowfish.generate_input_key(
            self.public_key.y)
        bf = blowfish.Blowfish(bfkey_decryption_key)

        self.blowfish_key = bf.decryption(key_encrypted)

        print("Decrypted Blowfish Key:\t\t", self.blowfish_key)
        print("Blowfish Key Exchange Successful!\n")

    def validate_payment(self, credit_card, security_code, amount, signature):
        """
        This function validates a payment.
        In addition to standard decryption of sent data,
        it also validates the authenticity of the sender's identity.
        """
        result = ecdsa.Ecdsa.verify(self.ec, credit_card, signature, self.Qa)
        if (result is True):
            print(
                "Elliptic Curve Digital Signature Algorithm (ECDSA) Check Passed Successfully!")
        else:
            print(
                "Invalid Signature - Elliptic Curve Digital Signature Algorithm (ECDSA)")
            exit(1)

        bf_key = blowfish.Blowfish.generate_input_key(self.blowfish_key)
        bf = blowfish.Blowfish(bf_key)

        decrypted_credit_card = bf.decryption(credit_card)
        decrypted_security_code = bf.decryption(security_code)

        print("Decrypted Credit Card:\t\t", decrypted_credit_card)
        print("Decrypted Security Code:\t", decrypted_security_code, "\n")
        print("Payment Successful,", amount, "Cookies Ordered!\n")
