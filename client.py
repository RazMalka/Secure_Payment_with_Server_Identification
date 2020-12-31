# This is a client

import sha256
import blowfish
import random

class Client():
    def __init__(self, server, ec):
        """
        This function initializes the client and its processes,
        including login and proceeding to order the cookies.
        """
        self.ec = ec
        self.generate_private_key()
        self.generate_public_key(server)
        self.username = ""
        validation_success = False
        while (validation_success is False):
            if (self.username is not ""):
                print("Login Failed!\nInvalid username or password - try again\n")
            username, password = self.login_prompt()
            print("\nSent to server verification ... \nAwaiting response ... \n")
            validation_success = server.validate_credentials(username, password)

        print("Login Successful!\n")
        
        self.blowfish_key_exchange(server)
        self.order_cookies(server)

    def generate_private_key(self):
        self.private_key_multiplier = random.randint(1, self.ec.q)
        self.private_key = self.ec.mul(self.ec.G, self.private_key_multiplier)

    def generate_public_key(self, server):
        self.public_key = server.generate_public_key(self.private_key)

    def login_prompt(self):
        """
        This function prompts a login form,
        and hashes the inputted password with a sha-256 hash.
        """
        self.username = input("Enter Username: ")
        input_password = sha256.sha_256(input("Enter Password: "))
        self.password = ''.join(str(w) for w in input_password)
        return self.username, self.password

    def blowfish_key_exchange(self, server):
        """
        This function allows ordering cookies.
        """
        
        # Here will be code for Elliptical Curve Digital Signature Algorithm and Key Exchange
        # ###################################################################################

        # Randomly Generated Blowfish Input Key
        self.blowfish_key = random.randint(10**10, 11**10 - 1)

        # Generate an Encryption Key for the Blowfish Key
        bfkey_encryption_key = blowfish.Blowfish.generate_input_key(self.public_key.y)
        bf = blowfish.Blowfish(bfkey_encryption_key)

        # It will be encrypted by the public key of elliptic curve
        # Before it will be sent to the server
        key_encrypted = bf.encryption(self.blowfish_key)

        print("\nBlowfish Key before Encryption:\t", self.blowfish_key)
        print("Encrypted Blowfish Key:\t\t", key_encrypted)
        print("\nSent to server authentication ... \nAwaiting response ... \n")

        # Additionally, we will need to pass here a digital signature somehow
        server.validate_blowfish_key_exchange(key_encrypted)

    def order_cookies(self, server):
        bf_key = blowfish.Blowfish.generate_input_key(self.blowfish_key)
        bf = blowfish.Blowfish(bf_key)

        credit_card = bf.encryption(int(input("Please Enter Credit Card:\t ")))
        security_code = bf.encryption(int(input("Please Enter Security Code:\t ")))

        print("Encrypted Credit Card:\t\t", credit_card)
        print("Encrypted Security Code:\t", security_code)
        print("\nSent to server authentication ... \nAwaiting response ... \n")

        # Additionally, we will need to pass here a digital signature somehow        
        server.validate_payment(credit_card, security_code)