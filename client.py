# This is a client

import blowfish
import random
import ecdsa
import hashlib


class Client():
    def __init__(self, server, ec):
        """
        This function initializes the client and its processes,
        including login and proceeding to order the cookies.
        """
        print("\n", "-"*24, "\n")

        self.ec = ec
        self.username = ""

        # Key Exchange
        self.key_exchange(server)
        print("Key Exchange Successful!\n\n", "-"*24, "\n")

        # Login Form
        self.login(server)
        print("\nLogin Successful!\n\n", "-"*24, "\n\n")

        # Payment Form
        self.pay(server)

    def key_exchange(self, server):
        """
        This function calls all of the relevant key exchange functions,
        including private, public, shared and blowfish keys.
        """
        self.generate_keys()
        self.generate_shared_key(server)
        self.blowfish_key_exchange(server)

    def generate_keys(self):
        """
        This function generates a private and public keys.
        """
        self.private_key = random.randint(1, self.ec.Prime)
        self.public_key = self.ec.mul(self.ec.G, self.private_key)

    def generate_shared_key(self, server):
        """
        This function generates a shared key.
        """
        signature = ecdsa.Ecdsa.sign(
            self.ec, self.public_key, self.private_key)
        # returned_public_key from server
        returned_public_key, returned_signature = server.generate_shared_key(
            self.public_key, signature)

        self.Qa = returned_public_key
        self.verify_signature(
            returned_public_key, returned_signature, "Public Key from Server")

        self.shared_key = self.ec.mul(returned_public_key, self.private_key)

        print("Generated Shared Key:\t\t", self.shared_key.x)
        print("\t\t\t\t", self.shared_key.y, "\n\n", "-"*24, "\n")

    def blowfish_key_exchange(self, server):
        """
        This function requests performing key exchange for blowfish.
        """
        # Randomly Generated 64-bit Blowfish Input Key
        self.blowfish_key = random.randint(2**54, 2**64 - 1)

        # Generate an Encryption Key for the Blowfish Key
        bfkey_encryption_key = blowfish.Blowfish.generate_input_key(
            self.shared_key.y)
        bf = blowfish.Blowfish(bfkey_encryption_key)

        # It will be encrypted by the public key of elliptic curve
        # Before it will be sent to the server
        key_encrypted = bf.encryption(self.blowfish_key)

        print("Blowfish Key before Encryption:\t", self.blowfish_key)
        print("Encrypted Blowfish Key:\t\t", key_encrypted)
        print("\nSent to server authentication ... \nAwaiting response ... \n")

        signature = ecdsa.Ecdsa.sign(
            self.ec, key_encrypted, self.private_key)
        server.validate_blowfish_key_exchange(key_encrypted, signature)

    def login(self, server):
        """
        This function takes care of a login loop until valid parameters are inputted.
        """
        validation_success = False
        while (validation_success is False):
            if (self.username is not ""):
                print("\nLogin Failed!\nInvalid username or password - try again\n")

            username, password = self.login_prompt()
            print("\nSent to server authentication ... \nAwaiting response ... \n")

            signature = ecdsa.Ecdsa.sign(
                self.ec, username + password, self.private_key)

            validation_success = server.validate_credentials(
                username, password, signature)

    def login_prompt(self):
        """
        This function prompts a login form,
        and hashes the inputted password with a sha-256 hash.
        """
        self.username = input("Enter Username: ")
        input_password = self.sha256(input("Enter Password: "))
        self.password = ''.join(str(w) for w in input_password)
        return self.username, self.password

    def pay(self, server):
        """
        This function requests performing a payment.
        It encrypts the data using blowfish,
        and also signs it to verify authenticity later on.
        """
        bf_key = blowfish.Blowfish.generate_input_key(self.blowfish_key)
        bf = blowfish.Blowfish(bf_key)

        credit_card = bf.encryption(int(input("Please Enter Credit Card:\t ")))
        security_code = bf.encryption(
            int(input("Please Enter Security Code:\t ")))
        amount = int(input("Amount of Cookies Wanted:\t "))

        print("Encrypted Credit Card:\t\t", credit_card)
        print("Encrypted Security Code:\t", security_code)
        print("\nSent to server authentication ... \nAwaiting response ... \n")

        signature = ecdsa.Ecdsa.sign(
            self.ec, credit_card + security_code, self.private_key)
        server.validate_payment(credit_card, security_code, amount, signature)

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

    def sha256(self, input_string):
        return hashlib.sha256(str(input_string).encode('utf-8')).hexdigest()
