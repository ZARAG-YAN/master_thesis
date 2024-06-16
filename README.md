# master_thesis
This repository is intended to store the thesis project.
Next to this README you can find the project zipped: thesis_project.zip.


###### *CONTENTS*

1. AUTHORS
2. ABOUT
3. PREREQUISITES
4. DIRECTORY STRUCTURE
5. USAGE
6. NOTES

######

1. **AUTHORS**

Zarine Grigoryan
E-mail:zarine.grigoryan@instigate.academy


2. **ABOUT**

The project is the virtual platform created by Proximus-foss tool.
The objective is to encrypt and decrypt input data, the other side captu


3. **PREREQUISITES**

The following tools and libraries should be installed before run of the project.

***Tools:***
 Open source Proximus-foss: https://sourceforge.net/projects/proximus-foss/

***Libraries:***
OpenSSL
    -openssl/rsa.h
    -openssl/pem.h
    -openssl/err.h

***OS:***
Linux operating system


4. **DIRECTORY STRUCTURE**

| File                    | Description                         |
| ----------------------- | ----------------------------------- |
| *Proximus_0.tcl*   |  Created by Proximus|
| *Proximus_1.tcl* |  Created by Proximus|
| *cpp_implementations*  | Created by Proximus |
| *file_paths*  |  Created by Proximus  |
| *hierarchical_implementations*   |  Created by Proximus|
| *interfaces*   |  Created by Proximus|
| *libraries*   |  Created by Proximus|
| *real_applications*  |  Created by Proximus|
| *real_designs*  |  Created by Proximus|
| *real_platforms*  |  Created by Proximus|
| *reporter*  |  Created by Proximus|
| *scenarios*   |  Created by Proximus|
| *sources* |  Created by Proximus|
| *test_data* |  Created by Proximus|
| *private_key.pem* | User provided private key|
| *publik_key.pem* | User provided public key|
| *input_data.json* | Input data file|
| *input.txt* |File which content we need to process |
| *output_data* | The output of MCU |
| *verifiable_chain.xml* |Project's XML file|

There are the following modules:
- read_data - for capturing input data
- read_key - for capturing public/private key
- write_data - for writing the result of MCU
- write_out - letting user know that the key in NVM successfully has been written. 
- UART1/2 - sending data from the read/write modules to MCU through the UART1 and 2
- NVM - memory segment. Using for storing keys in memory segment
- MCU
  - Check_Data - Checking data and depends on the key, writing into memory 
  - Parse_Data - Parsing input data to check the command provided through the JSON file for encryption and decryption. 
  - Encryption/Decryption
  - Check_Out - Checking whether encryption/decryption succeeded or not.

For Encryption/Decryption using OpenSSL Library.

2. **ABOUT**

*Unzip zipped file*
`unzip thesis_project.zip`

*Run Proximus*
`<installed_proximus_path>/proximus-foss`

Run project from the Proximus by opening *verifiable_chain.xml* XML file from the Proximus tool.


The Encryption/Description module uses the following OpenSSL's operations:
- Encrypt data with a public key (encryptWithPublicKey).
- Encrypt data with a private key (encryptWithPrivateKey).
- Decrypt data with a private key (decryptWithPrivateKey).
- Decrypt data with a public key (decryptWithPublicKey).

**Explanation**
Initialization: Initialize OpenSSL's algorithms and error strings.

Load RSA Keys:
The loadPublicKey function loads a public key from a PEM-encoded string.
The loadPrivateKey function loads a private key from a PEM-encoded string.
BIO_new_mem_buf creates a memory BIO for reading the PEM key.
PEM_read_bio_RSA_PUBKEY and PEM_read_bio_RSAPrivateKey read the keys from the BIO.

*Encryption and Decryption:*
-Encrypt with Public Key:
    The encryptWithPublicKey function encrypts the plaintext using the public key with RSA_public_encrypt and RSA_PKCS1_OAEP_PADDING for padding.
`int encryptWithPublicKey(RSA* rsa, const std::string& plaintext, unsigned char* ciphertext) {
    int result = RSA_public_encrypt(plaintext.size(), (const unsigned char*)plaintext.c_str(), ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) handleOpenSSLErrors();
    return result;
}`
-Decrypt with Private Key:
    The decryptWithPrivateKey function decrypts the ciphertext using the private key with RSA_private_decrypt and RSA_PKCS1_OAEP_PADDING for padding.
`int decryptWithPrivateKey(RSA* rsa, const unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext) {
    int result = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) handleOpenSSLErrors();
    return result;
}`

-Encrypt with Private Key:
    The encryptWithPrivateKey function encrypts the plaintext using the private key with RSA_private_encrypt and RSA_PKCS1_PADDING for padding (typically for digital signatures).
`int encryptWithPrivateKey(RSA* rsa, const std::string& plaintext, unsigned char* ciphertext) {
    int result = RSA_private_encrypt(plaintext.size(), (const unsigned char*)plaintext.c_str(), ciphertext, rsa, RSA_PKCS1_PADDING);
    if (result == -1) handleOpenSSLErrors();
    return result;
}`


-Decrypt with Public Key:
    The decryptWithPublicKey function decrypts the ciphertext using the public key with RSA_public_decrypt and RSA_PKCS1_PADDING for padding (typically for verifying digital signatures).

`int decryptWithPublicKey(RSA* rsa, const unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext) {
    int result = RSA_public_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_PADDING);
    if (result == -1) handleOpenSSLErrors();
    return result;
}`


Cleanup: Free the loaded keys and OpenSSL structures to prevent memory leaks.
