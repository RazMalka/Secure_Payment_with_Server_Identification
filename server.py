
# This is a server

import blowfish

class Server():
    def __init__(self):
        """
        This function is a constructor that initializes
        simulated variables username and hashed password.
        """
        self.simulation_username = "dima"
        self.simulation_hashed_password = "3ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"

    def validate_credentials(self, username, password):
        """
        This function validates credentials.
        For simulation purposes, it is for a predefined user "Dima",
        with password 1234 hashed with 256-sha algorithm.
        """
        return (username == self.simulation_username and password == self.simulation_hashed_password)

    def validate_payment(self, credit_card, security_code, key):
        # It will be decrypted by the public key of elliptic curve
        # After it is received by the server
        decrypted_key = key.copy()

        bf = blowfish.Blowfish(decrypted_key)
        decrypted_credit_card = bf.decryption(credit_card)
        decrypted_security_code = bf.decryption(security_code)
        print("Decrypted Credit Card:\t\t", decrypted_credit_card)
        print("Decrypted Security Code:\t", decrypted_security_code, "\n")
        
        # ...

        print("Authentication Successful!\n")