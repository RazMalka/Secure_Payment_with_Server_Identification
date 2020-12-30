# This is a client

import sha256
import blowfish

class Client():
    def __init__(self, server):
        """
        This function initializes the client and its processes,
        including login and proceeding to order the cookies.
        """
        self.username = ""
        validation_success = False
        while (validation_success is False):
            if (self.username is not ""):
                print("Login Failed!\nInvalid username or password - try again\n")
            username, password = self.login_prompt()
            print("\nSent to server verification ... \nAwaiting response ... \n")
            validation_success = server.validate_credentials(username, password)

        print("Login Successful!\n")
        
        self.order_cookies(server)

    def login_prompt(self):
        """
        This function prompts a login form,
        and hashes the inputted password with a sha-256 hash.
        """
        self.username = input("Enter Username: ")
        input_password = sha256.sha_256(input("Enter Password: "))
        self.password = ''.join(str(w) for w in input_password)
        return self.username, self.password

    def order_cookies(self, server):
        """
        This function allows ordering cookies.
        """
        
        # Here will be code for Elliptical Curve Digital Signature Algorithm and Key Exchange
        # ###################################################################################

        # Generated Somehow from a text or something
        key = [ 0x61626364, 0x65666768, 0x696a6b6c, 0x6d6e6f70,
            0x71727374, 0x75767778, 0x797a6162, 0x63646566,
            0x6768696a, 0x6b6c6d6e, 0x6f707172, 0x73747576,
            0x7778797a, 0x61626364 ]

        # It will be encrypted by the public key of elliptic curve
        # Before it will be sent to the server
        key_encrypted = key.copy()

        bf = blowfish.Blowfish(key)
        credit_card = bf.encryption(int(input("Please Enter Credit Card:\t ")))
        security_code = bf.encryption(int(input("Please Enter Security Code:\t ")))

        print("\nEncrypted Credit Card:\t\t", credit_card)
        print("Encrypted Security Code:\t", security_code)

        print("\nSent to server authentication ... \nAwaiting response ... \n")
        # Additionally, we will need to pass here a digital signature somehow        
        server.validate_payment(credit_card, security_code, key_encrypted)