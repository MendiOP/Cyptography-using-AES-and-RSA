# Cryptography using AES and RSA

## Overview

This codebase provides a basic implementation of cryptography using **AES** (Advanced Encryption Standard) and **RSA** (Rivest-Shamir-Adleman) algorithms. It is written in Python and utilizes the **BitVector** library for bit-level operations.

---

## Features

- **AES Encryption**: Implements the AES encryption algorithm with a 128-bit key size.
- **RSA Encryption**: Implements the RSA encryption algorithm with variable key sizes (16, 32, 64, and 128 bits).
- **Key Generation**: Provides key generation for both AES and RSA algorithms.
- **Encryption and Decryption**: Includes functions for encrypting and decrypting messages using both AES and RSA algorithms.
- **Socket Programming**: Demonstrates a simple client-server architecture using socket programming for secure communication.

---

## Code Structure

The codebase is organized into the following files:

- **`Alice.py`**: Contains the server-side code for the client-server architecture.
- **`Bob.py`**: Contains the client-side code for the client-server architecture.
- **`AES.py`**: Implements the AES encryption algorithm.
- **`rsa.py`**: Implements the RSA encryption algorithm.

---

## Usage

To run the code, follow these steps:

1. Install the required libraries by running:

   ```bash
   pip install bitvector

    Run the server-side code:
   ```

python Alice.py

Run the client-side code:

    python Bob.py

Example Use Cases

    Secure Communication: The client-server architecture can facilitate secure communication between two parties.
    Data Encryption: AES and RSA algorithms can be applied to encrypt sensitive data.

Limitations

    Key Size: The RSA algorithm's key size is limited to 128 bits.
    Security: Additional security measures like authentication or integrity checks are not implemented.

Future Work

    Optimization: Improve the code for better performance.
    Security Enhancements: Introduce authentication, integrity checks, and other security measures.

License

This code is released under the MIT License.
