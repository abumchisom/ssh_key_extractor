# SSH Key Information Extractor

A Python script that extracts and displays detailed information from SSH key files. The script supports both private and public keys in OpenSSH and PEM formats.

## Features

- Handles private keys (encrypted and unencrypted) and public keys.
- Supports RSA, DSA, ECDSA, and Ed25519 algorithms.
- Extracts key-specific details such as key size, algorithm, curve name (for ECDSA), and public exponent (for RSA).
- Displays the original content of the key file.
- Generates the public key in OpenSSH format (if applicable).
- Calculates and displays the fingerprint of the key (if possible).
- User-friendly interactive CLI interface.

## Requirements

- Python 3.6 or higher
- The following Python libraries:
  - `cryptography`
  - `os`
  - `base64`
  - `binascii`

You can install the required libraries using `pip`:

```sh
pip install cryptography
```

## Author
- **[Joseph Chisom Ofonagoro and Assistant](https://x.com/abumchisom)**
