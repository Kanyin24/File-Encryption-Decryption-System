from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def chacha20_encrypt(plain_text, key):
    # Set the nonce to 1 (arbitrary value)
    nonce = bytes([1])

    # Create a ChaCha20 cipher
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the plaintext
    cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()

    return cipher_text, nonce

def chacha20_decrypt(cipher_text, key, nonce):
    # Create a ChaCha20 cipher
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

    return decrypted_data.decode()

def main():
    plain_text = input("Enter the plain text to encrypt: ")
    key = input("Enter the encryption key (must be 256 bits): ")

    # Ensure key length is 256 bits (32 bytes)
    if len(key) != 32:
        print("Error: Key must be 256 bits (32 bytes) long.")
        return

    # Encrypt the plain text
    cipher_text, nonce = chacha20_encrypt(plain_text, key.encode())

    print("\nCipher Text:", cipher_text.hex())
    print("Nonce:", nonce.hex())

    # Decrypt the cipher text
    decrypted_text = chacha20_decrypt(cipher_text, key.encode(), nonce)
    print("\nDecrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
