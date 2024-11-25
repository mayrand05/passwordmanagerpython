import os
import base64
import json
import getpass
import time  
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pyotp


MASTER_PASSWORD_FILE = "master_password.json"
PASSWORD_VAULT_FILE = "password_vault.enc"


COOLDOWN_SECONDS = 3


def hash_master_password(master_password, iterations=310_000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return salt, hashed_password


def verify_master_password(stored_salt, stored_hash, master_password, iterations=310_000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=stored_salt,
        iterations=iterations,
        backend=default_backend(),
    )
    try:
        derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return derived_key == stored_hash
    except Exception:
        return False

def save_master_password(salt, hashed_password):
    totp_secret = pyotp.random_base32() 
    print("Generated TOTP Secret:", totp_secret) 
    with open(MASTER_PASSWORD_FILE, "w") as file:
        data = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "hash": hashed_password.decode(),
            "totp_secret": totp_secret,
        }
        json.dump(data, file)
    return totp_secret



def load_master_password():
    try:
        with open(MASTER_PASSWORD_FILE, "r") as file:
            data = json.load(file)
            salt = base64.urlsafe_b64decode(data["salt"])
            hashed_password = data["hash"].encode()
            totp_secret = data["totp_secret"]
            return salt, hashed_password, totp_secret
    except FileNotFoundError:
        return None, None, None


def encrypt_data(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext


def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()


def save_vault(key, vault):
    encrypted_vault = encrypt_data(key, json.dumps(vault))
    with open(PASSWORD_VAULT_FILE, "wb") as file:
        file.write(encrypted_vault)


def load_vault(key):
    if not os.path.exists(PASSWORD_VAULT_FILE):
        return {}
    with open(PASSWORD_VAULT_FILE, "rb") as file:
        encrypted_vault = file.read()
        return json.loads(decrypt_data(key, encrypted_vault))


def password_manager(key):
    vault = load_vault(key)
    while True:
        print("\nPassword Manager Menu Options:")
        print("1. Add a new password")
        print("2. See a password")
        print("3. Exit")
        choice = input("Enter your choice number: ")

        if choice == "1":
            site = input("Enter the site name: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            vault[site] = {"username": username, "password": password}
            save_vault(key, vault)
            print("Your password was saved!")
        elif choice == "2":
            site = input("Enter the site name: ")
            if site in vault:
                print(f"Username: {vault[site]['username']}")
                print(f"Password: {vault[site]['password']}")
            else:
                print("No password found for this site.")
        elif choice == "3":
            print("Exiting Password Manager.")
            break
        else:
            print("Invalid choice. Please try again!!!!!")

def main():
    stored_salt, stored_hash, totp_secret = load_master_password()

    if stored_salt is None or stored_hash is None:
        print("No master password found, Please set one up.")
        master_password = getpass.getpass("Enter a new master password: ")
        confirm_password = getpass.getpass("Confirm your master password: ")

        if master_password != confirm_password:
            print("Your given passwords do not match. Try again!")
            return

        salt, hashed_password = hash_master_password(master_password)
        totp_secret = save_master_password(salt, hashed_password)  # Save and retrieve the secret
        print("Master password set successfully!")
        print("TOTP Setup Key:", totp_secret)
        print("Use this key to set up your authenticator app.")
    else:
        print("Master password exists. Please log in.")
        while True:
            master_password = getpass.getpass("Enter your master password: ")

            if not verify_master_password(stored_salt, stored_hash, master_password):
                print("Login failed. Incorrect master password.")
                print(f"Please wait {COOLDOWN_SECONDS} seconds before trying again...")
                time.sleep(COOLDOWN_SECONDS)
                continue

            totp = pyotp.TOTP(totp_secret, digits=6)  # Set TOTP to generate 8 digits
            otp = input("Enter the 2FA code from your authenticator app: ")
            if not totp.verify(otp):
                print("2FA verification failed.")
                continue

            print("Login successful! Access granted to the password manager.")
            derived_key = base64.urlsafe_b64decode(stored_hash)
            password_manager(derived_key)
            break


if __name__ == "__main__":
    main()
