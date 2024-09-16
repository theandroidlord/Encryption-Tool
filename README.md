File Encryption and Decryption Tool

This is a simple command-line tool written in C that uses the AES-256 encryption algorithm to encrypt and decrypt files. The tool generates a random 32-byte key for encryption and saves it to a file named `decrypt_code.txt` for later decryption.

## Features
- Encrypt files using AES-256 encryption.
- Decrypt files using the saved key.
- Automatically generates and saves a random 32-byte key.

## Prerequisite 
- `OpenSSL`

## Installation

Step 1: Install Required Packages
Install the necessary packages for compiling and running C programs:

`apt install clang openssl`

Step 2: Compile the Program
Compile your C program using clang:

`clang -o encrypt_tool encrypt_tool.c -lssl -lcrypto`

# Usage

Encrypt a File
To encrypt a file, use the following command:

`./encrypt_tool encrypt <input file> <output file>`

Example:

`./encrypt_tool encrypt input.txt encrypted.bin`

This will generate a random 32-byte key and save it to decrypt_code.txt.

Decrypt a File
To decrypt a file, use the following command:

`./encrypt_tool decrypt <input file> <output file>`

Example:

`./encrypt_tool decrypt encrypted.bin decrypted.txt`

This will read the key from decrypt_code.txt and use it to decrypt the file.

Encryption Example Workflow in Cli
Create a Sample Input File:
echo "This is a test file." > input.txt

Encrypt the File:
`./encrypt_tool encrypt input.txt encrypted.bin`

Decrypt the File:
`./encrypt_tool decrypt encrypted.bin decrypted.txt`

Check the Decrypted File:
`cat decrypted.txt`

View the Generated Key:
`cat decrypt_code.txt`

# contact
sr.developer@linuxmail.org
