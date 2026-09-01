#!/usr/bin/env python3
"""
fernet_password_encryptor.py

Lets the user type in a password (or any secret string), encrypts it using
the Fernet symmetric encryption scheme (from the 'cryptography' library),
and then decrypts it back to prove the round trip works.

Fernet uses AES-128 in CBC mode with HMAC-SHA256 for authentication, and
guarantees that a message encrypted with it cannot be manipulated or read
without the key.

Requires:
    pip install cryptography

Usage:
    python3 fernet_password_encryptor.py
"""

import getpass
from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> bytes:
    """Generate a new Fernet encryption key.

    In a real application this key must be stored securely (e.g. in an
    environment variable, a secrets manager, or a key vault) and reused,
    otherwise previously encrypted data can no longer be decrypted.
    """
    return Fernet.generate_key()


def encrypt_password(plain_text_password: str, key: bytes) -> bytes:
    """Encrypt a plain-text password using the given Fernet key.

    Args:
        plain_text_password: The password to encrypt.
        key: The Fernet key used to encrypt/decrypt.

    Returns:
        The encrypted token as bytes.
    """
    fernet = Fernet(key)
    encrypted_token = fernet.encrypt(plain_text_password.encode("utf-8"))
    return encrypted_token


def decrypt_password(encrypted_token: bytes, key: bytes) -> str:
    """Decrypt a Fernet token back into the original plain-text password.

    Args:
        encrypted_token: The encrypted token produced by encrypt_password().
        key: The same Fernet key that was used to encrypt.

    Returns:
        The decrypted plain-text password.

    Raises:
        InvalidToken: If the key is wrong or the token has been tampered with.
    """
    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(encrypted_token)
    return decrypted_bytes.decode("utf-8")


def main():
    print("=== Fernet Password Encryptor ===\n")

    # getpass hides the input from the terminal, like a normal password prompt
    plain_text_password = getpass.getpass("Enter the password to encrypt: ")

    if not plain_text_password:
        print("No password entered. Exiting.")
        return

    # Step 1: generate a key for this session
    key = generate_key()
    print(f"\nGenerated Fernet key: {key.decode('utf-8')}")
    print("(Keep this key safe - it is required to decrypt the password later)")

    # Step 2: encrypt
    encrypted_token = encrypt_password(plain_text_password, key)
    print(f"\nEncrypted password: {encrypted_token.decode('utf-8')}")

    # Step 3: decrypt, to demonstrate the round trip
    try:
        decrypted_password = decrypt_password(encrypted_token, key)
        print(f"\nDecrypted password: {decrypted_password}")

        if decrypted_password == plain_text_password:
            print("Success: decrypted password matches the original input.")
        else:
            print("Warning: decrypted password does NOT match the original input.")

    except InvalidToken:
        print("Error: could not decrypt the token. The key may be invalid or the token corrupted.")


if __name__ == "__main__":
    main()
