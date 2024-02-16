## Course project for CS 5930.

### NAME OF PROJECT: Confidentiality and Integrity Crypto App
---

### NAME OF PROGRAMMER: Simeon Wuthier
---

### STATEMENT:
I have neither given nor received unauthorized assistance on this work.
---
### SPECIAL INSTRUCTIONS:
---

The core of this application in its entirety is located in the python file: `application.py`. However additional files exist for additional convenience of the user. This application is composed of the following files:

 * `application.py`: The main application, which asks the user to select one of six options:
 * * 1 - Generate a Keypair
 * * 2 - Encrypt a file
 * * 3 - Decrypt a file
 * * 4 - Generate a file signature
 * * 5 - Verify a file signature
 * * 6 - Exit the application

 * `install_dependencies.bat`: Windows Batch file to automatically install all prerequisites required to run the application.

 * `application.bat`: Windows Batch file to automatically run the application.

 * `.gitignore`: The list of files that cannot not be uploaded to GitHub. Specifically, any file ending in `.pem` (public/private key pairs), `.enc` (ciphertext files), and `.txt` (plaintext files and digital signatures) are prevented from being uploaded to GitHub. 

 * `LICENSE`: The MIT License that grants open source access to the files of this application when given consent from the original author.


---

To run the application, first ensure that you have ran `install_dependencies.bat` at least once. Then run the application by double clicking on `application.bat`. The following text interface will display:
```
Please select an operation:
  1 - Generate Keypair
  2 - Encrypt File
  3 - Decrypt File
  4 - Generate File Signature
  5 - Verify File Signature
  6 - Exit Application

Your selection:
```

 * When selection: `1`:
```
You selected "Generate Keypair".

Generated:
  -  private_key.pem
  -  public_key.pem
RSA keypair generated successfully.
```
Two RSA 2048 files will be created:
* outputs/private_key.pem
* outputs/public_key.pem

When selection: `2`:
```
List of files:
  File 1  -  .gitignore
  File 2  -  application.bat
  File 3  -  application.py
  File 4  -  install_dependencies.bat
  File 5  -  LICENSE
  File 6  -  README.md

Please select a file: 5
You selected "LICENSE".
File encrypted successfully as outputs\encrypted_file.enc
File encrypted successfully as LICENSE

Its contents are:
b'{n\xad\x98\x1a\xd3\x7fa$]\\\x9c\xad\xf7h\x02T\xec...
```
* Upon selecting a file, the app will encrypt a file using AES with CBC mode:
* * outputs/encrypted_file.enc

When selection: `3`:
```
You selected "Decrypt File".

File decrypted successfully as outputs\decrypted_file.txt
File decrypted successfully as outputs\decrypted_file.txt

Its contents are:
b'MIT License\r\n\r\nCopyright (c) 2024 Simeon Wuthier...
```
* Upon selecting a ciphertext, the app will decrypt it to:
* * outputs/decrypted_file.txt

When selection: `4`:
```
You selected "Generate File Signature".

List of files:
  File 1  -  .gitignore
  File 2  -  application.bat
  File 3  -  application.py
  File 4  -  install_dependencies.bat
  File 5  -  LICENSE
  File 6  -  README.md

Please select a file: 3
You selected "application.py".
Signature generated successfully as outputs\signature.txt
Signature generated successfully as application.py

Its contents are:
b'r`v\xcdz\x8d\xf8\x06\xc3\x80\xadi\xfc
```
* Upon selecting a file, the app will generate a digital signature using the RSA algorithm with PSS (Probabilistic Signature Scheme) padding, generating:
* * outputs/signature.txt

When selection: `5`:
```
You selected "Verify File Signature".


List of files:
  File 1  -  .gitignore
  File 2  -  application.bat
  File 3  -  application.py
  File 4  -  install_dependencies.bat
  File 5  -  LICENSE
  File 6  -  README.md

Please select a file: 3
You selected "application.py".
Signature was successfully verified and is valid.
```
* The signature verification will output success or failure, for if the digital signature is valid or invalid.

---

### PROBLEM DESCRIPTION AND REMEDIATION:

The Confidentiality and Integrity Crypto App was initially developed to enhance data confidentiality, a fundamental aspect of the CIA triad. This objective was achieved through the implementation of file encryption using the AES algorithm in CBC mode. Recognizing the indispensable role of data integrity alongside confidentiality, the application was further augmented with digital signature capabilities. This addition enables users to sign files using RSA with PSS padding, ensuring the authenticity and unaltered state of data.

The application supports two critical security principles: confidentiality, through encryption, and integrity, via digital signatures. Encryption safeguards data from unauthorized access, while digital signatures provide a mechanism to verifying data authenticity and integrity. This dual functionality addresses the core requirements of secure data handling by preventing unauthorized disclosure and ensuring data remains unchanged from its original state.

Structured with a user-centric interface, the app facilitates key cryptographic operations: RSA keypair generation, file encryption and decryption, and digital signature generation and verification. It is complemented by utility scripts for dependency management and execution, alongside a .gitignore file to exclude sensitive cryptographic materials from version control, reinforcing security practices.

---

