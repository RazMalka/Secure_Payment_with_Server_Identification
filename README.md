### Secure Payment with Server Identification using Elliptic Protocol Digital Signature and Key Exchange, Blowfish Cipher and SHA-256.

![Build Status](http://img.shields.io/travis/badges/badgerbadgerbadger.svg?style=flat-square) 

### Brief
```
Implementation of a Secure Payment system that uses Elliptic Curve protocol 
for Digital Signature (ECDSA) and Key Exchange, performs Encryption-Decryption 
with the Blowfish cipher and hashes with SHA-256.

It includes a terminal user interface which allows to evaluate and control 
the input and the output, which includes login credentials (username, password), 
credit info (card number, security code) and amount of order.

DISCLAIMER:
This project is non-profit and is intended to serve for educational purposes only.
It is not meant to infringe copyright rights by any means.
Please notify the repository owner of any infringements and they will be removed.
```
### Research Papers
- [B. Schneier, Description of a New Variable-Length Key, 64-Bit Block Cipher - Blowfish](https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html)
### Installing and Running
- No Dependencies Required
- Clone the Project
```
git clone https://github.com/RazMalka/SPBF.git
cd SPBF
```
- Execute from Anaconda CLI
```
cd ..
conda init
conda activate base
python simulation.py
```
- Run Example
```
ECDSA Check Passed Successfully! - Public Key from Client
ECDSA Check Passed Successfully! - Public Key from Server
Generated Shared Key: 25394511812778603619227816989027563366746218111054367323587477136122146428502                      
                      60680758641743372276633753427056444884877625535240344639540476248561648353055
 ------------------------
Blowfish Key before Encryption:  6116748057251957367
Encrypted Blowfish Key:          3158364940711033323

Sent to server authentication ...
Awaiting response ...

ECDSA Check Passed Successfully! - Received Blowfish Key
Decrypted Blowfish Key:          6116748057251957367
Blowfish Key Exchange Successful!
Key Exchange Successful!
 ------------------------
Enter Username: dima
Enter Password: 1234

Sent to server authentication ...
Awaiting response ...

Received Hashed Password:    03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
Hashed Password in Database: 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
ECDSA Check Passed Successfully! - Login Credentials
Login Successful!
 ------------------------
Please Enter Credit Card:        4580111122223333
Please Enter Security Code:      157
Number of Cookies Wanted:        300
Encrypted Credit Card:           12189402448596447618
Encrypted Security Code:         1970966770398565105

Sent to server authentication ...
Awaiting response ...

ECDSA Check Passed Successfully! - Received Credit Info
Decrypted Credit Card:           4580111122223333
Decrypted Security Code:         157

Payment Successful, 300 Cookies Ordered!
```
### Prerequisites and Libraries
- VSCode (IDE)
- Anaconda (Python3 Distribution)
- Numpy (Scientific Calculations)
