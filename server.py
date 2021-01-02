
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
        self.simulation_username = "dima"
        self.simulation_hashed_password = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"

        # Key Exchange
        self.generate_keys()

    def generate_keys(self):
        """
        This function generates a private and public keys.
        """
        self.private_key = random.randint(1, self.ec.q)
        self.public_key = self.ec.mul(self.ec.G, self.private_key)

    def generate_shared_key(self, key, signature):
        """
        This function generates a shared key.
        """
        self.Qa = key  # Qa is the public key used to verify signatures
        self.verify_signature(
            key, signature, "Public Key from Client")

        self.shared_key = self.ec.mul(
            key, self.private_key)  # k1 * k2 * G

        returned_signature = ecdsa.Ecdsa.sign(
            self.ec, self.public_key, self.private_key)
        return self.public_key, returned_signature

    def validate_credentials(self, username, password, signature):
        """
        This function validates credentials.
        For simulation purposes, it is for a predefined user "Dima",
        with password 1234 hashed with 256-sha algorithm.
        """
        print("Received Hashed Password:\t\t", password)
        print("Hashed Password in Database:\t\t",
              self.simulation_hashed_password)
        self.verify_signature(username + password, signature,
                              "Login Credentials")

        return (username == self.simulation_username and password == self.simulation_hashed_password)

    def validate_blowfish_key_exchange(self, key_encrypted, signature):
        """
        This function validates the key exchange for blowfish.
        """
        self.verify_signature(key_encrypted, signature,
                              "Received Blowfish Key")

        bfkey_decryption_key = blowfish.Blowfish.generate_input_key(
            self.shared_key.y)
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
        self.verify_signature(credit_card + security_code,
                              signature, "Received Credit Info")

        bf_key = blowfish.Blowfish.generate_input_key(self.blowfish_key)
        bf = blowfish.Blowfish(bf_key)

        decrypted_credit_card = bf.decryption(credit_card)
        decrypted_security_code = bf.decryption(security_code)

        print("Decrypted Credit Card:\t\t", decrypted_credit_card)
        print("Decrypted Security Code:\t", decrypted_security_code, "\n")
        print("Payment Successful,", amount, "Cookies Ordered!\n")

    def verify_signature(self, message, signature, purpose):
        """
        This function calls the ECDSA verify function with required parameters,
        and prints the result. If the result is false, it exists with code 1.
        """
        result = ecdsa.Ecdsa.verify(
            self.ec, message, signature, self.Qa)
        if (result is True):
            print(
                "ECDSA Check Passed Successfully! -", purpose)
        else:
            print(
                "Invalid Signature - Elliptic Curve Digital Signature Algorithm (ECDSA) -", purpose)
            exit(1)
