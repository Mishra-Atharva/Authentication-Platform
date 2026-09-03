import hashlib
import argparse
import hmac
import secrets
import os
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

class User:

    # Initalization
    def __init__(self, p_user: str, p_salt: bytes, p_passwd_hash: hex, p_iteration, p_clearnace_level: int = 0):
        self.name: str = p_user
        self.salt: bytes = bytes.fromhex(p_salt)
        self.passwd_hash: hex = p_passwd_hash
        self.iterations: int = int(p_iteration)
        self.clearance_level: int = int(p_clearnace_level)
    
    # Returns the user's clearance level
    def set_clearance_level(self, level: int) -> None:
        self.clearance_level = level

    # Returns the user's details in a specific format
    def __str__(self):
        return f"{self.name}|{self.salt.hex()}|{self.passwd_hash}|{self.iterations}|{self.clearance_level}\n"
        
class File:

    meta_data: Path = os.getenv("META_DATA")

    def __init__(self, p_name: str, p_clearance_level: int) -> None:

        self.name = p_name
        self.clearance_level = p_clearance_level
        self.path = Path(os.getenv("DIRECTORY") + "/" + self.name)

    # Create a new file
    def create(self) -> bool:

        try:
            # Create file
            open(self.path, 'x')

            # Add file meta data
            with open(self.meta_data, "a") as file:
                file.write(f"{self.name}|{self.clearance_level}")

            return True

        except FileExistsError as e:
            print(f"[!] File Error: {e}")

        return False

    # Reads the file
    def read(self) -> None:

        try:
            with open(self.path, 'r') as file:
                print(file.read())

        except FileNotFoundError as e:
            print(f"[!] File Error: {e}")

    def write(self) -> None:

        with open(self.path, "a") as file:
            data = input("[q to finish] >>> ")

            while (data != "q"):
                file.write(data + "\n")
                data = input("[q to finish] >>> ")

            print("[*] File saved!") 

        time.sleep(1)

    # Delets the file
    def delete(self) -> None:

        try:
            os.remove(self.path)

        except Exception as e:
            print(f"[!] Error: {e}")

class FileManager:

    # Keeps tracks of all the files
    stored_files = []

    # Initalizing
    def __init__(self, p_key: bytes):
        self.key: bytes = p_key
        self._path = Path(os.getenv("DIRECTORY"))

        # Checking if the folder exists
        if (self._path.exists()):

            # Loads all the files into the stored_files array
            for file in self._path.iterdir():
                new_file = File(file.name, 0)
                self.stored_files.append(new_file)

        else:
            self._path.mkdir(exist_ok=True)

    # Creates the file
    def create(self, file_name: str, cl: int = 0) -> bool:
        new_file = File(file_name, cl)

        if (new_file.create()):
            self.stored_files.append(new_file)
            return True 
        
        return False

    # Read a file
    def read(self, file: int) -> None:
        self.stored_files[file-1].read()

    # Write to a file
    def write(self, file: int) -> None:
        self.stored_files[file-1].write()

    # Deletes the file
    def delete(self, file: int) -> bool:
        try:
            self.stored_files[file-1].delete()
            self.stored_files.pop(file-1)
            return True
        
        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    # Prints out all the files in a list format
    def list_files(self) -> bool:
        if (len(self.stored_files) == 0):
            return False
        
        for idx, file in enumerate(self.stored_files):
            print(f"[{idx+1}] {file.name}")

        return True

    # Encrypt a file
    def encrypt_doc(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        doc_hash = hashlib.sha256(ciphertext).digest()
        return iv + doc_hash + ciphertext

    # Decrypt a file
    def decrypt_doc(self, blob: bytes) -> bytes:
        iv, stored_hash, ciphertext = blob[:16], blob[16:48], blob[48:]
        if not hmac.compare_digest(hashlib.sha256(ciphertext).digest(), stored_hash):
            raise ValueError("Integrity check failed - file may have be tampered with")
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize() 

class Authenticator:

    # Holds the current user
    user: User = None
    users_list: list[User] = []

    # Default values for Salt and Hashing
    root_user = os.getenv("MASTER_USER")
    d_bits: int = int(os.getenv("BIT_SIZE"))
    d_byte_size: int = int(os.getenv("BYTE_SIZE"))
    d_iteration: int = int(os.getenv("ITERATION"))

    # File Paths
    master_database: Path = Path(os.getenv("MASTER_DATA"))
    database: Path = Path(os.getenv("DATABASE"))

    # Initalization
    def __init__(self): 

        # If a master user doesn't exist
        if (not(Path("master.txt").exists())):

            # Getting information for master user from the .env file
            _user = os.getenv("MASTER_USER")
            _passwd = os.getenv("MASTER_PASSWORD").encode("utf-8")

            # Salt + Hashing
            self.salt = Authenticator.gen_salt()
            salt_byte = self.salt.to_bytes(self.d_byte_size, byteorder='big')
            salt_hex = salt_byte.hex()
            self.passwd_hash = Authenticator.hash_passwd(_passwd, salt_byte, self.d_iteration, self.d_byte_size)

            # AES-Key
            kdf_salt = Authenticator.gen_salt()
            kdf_salt_bytes = kdf_salt.to_bytes(self.d_byte_size, "big")
            self.key = bytes.fromhex(Authenticator.hash_passwd(_passwd, kdf_salt_bytes, self.d_iteration, self.d_byte_size))

            # Saving Master user's details
            data = User(_user, salt_hex, self.passwd_hash, self.d_iteration, -1)
            if (Authenticator.save(data, self.master_database, 'w')):

                # Saving the salt for AES-Key
                with open(Authenticator.master_database, 'a') as file:
                    file.write(kdf_salt_bytes.hex())
                print("[*] Master User Created!")

        else:
            _passwd = os.getenv("MASTER_PASSWORD").encode("utf-8")

            with open(Authenticator.master_database, "r") as file:
                lines = file.readlines()
                kdf_salt_bytes = bytes.fromhex(lines[1].strip())
                self.key = bytes.fromhex(Authenticator.hash_passwd(_passwd, kdf_salt_bytes, self.d_iteration, self.d_byte_size))


        # Store all users in users_list
        if (self.database.exists()):
            with open(self.database, 'r') as file:
                
                for line in file:
                    # Unpacking the list of string into arguments
                    _user = User(*line.strip().split("|"))
                    Authenticator.users_list.append(_user)

    # List users
    @staticmethod
    def list_users() -> int:
        for idx, _user in enumerate(Authenticator.users_list):
            print(f"[{idx+1}] {_user.name.capitalize()}")

        return len(Authenticator.users_list)

    @staticmethod
    def set_clearanace_level(p_user: int) -> None:
        _user = Authenticator.users_list[p_user-1]
        print(f"[ {_user.name.capitalize()} ]\n\nClearance Level: {_user.clearance_level}\n")

        level = int((input("Set Clearance Level [0/1/2]>> ")))

        while (level < 0 or level > 2):
            level = int((input("Set Clearance Level [0/1/2]>> ")))

        _user.set_clearance_level(level)

        for s_user in Authenticator.users_list:
            Authenticator.save(s_user, Authenticator.database, "w")

        print("[*] Clearance Level Updated!")

    # Generates a random salt
    @staticmethod
    def gen_salt(_bytes: int = d_bits) -> int:
        try:
            salt = secrets.randbits(_bytes)
            return salt
        
        except Exception as e:
            print(f"[!] Error generating salt: {e}")
            print("[*] Shuting down!")

        sys.exit(1)

    # Geenerates a hash
    @staticmethod
    def hash_passwd(password: bytes, salt: bytes, iter: int = d_iteration, req_size: int = d_byte_size) -> hex:

        try:
            # Hashing the password using the SHA256 hashing algorithm
            passwd_hash = hashlib.pbkdf2_hmac('sha256', password, salt, iter, req_size)
            return passwd_hash.hex()

        except Exception as e:
            print(f"[!] Error hashing the password: {e}")
            print(f"[*] Shutting down.")

        exit(1)

    # Checks if the hashed passwords matches
    def verify(self, curr_hash: hex, stored_hash: hex) -> bool:
        return hmac.compare_digest(curr_hash, stored_hash)

    @staticmethod
    # Save the user's credentials to a file
    def save(user: User, path: Path, mode: str = "a") -> bool:
        try:
            with open(path, mode) as file:
                file.write(str(user))
            return True 
        
        except FileNotFoundError as e:
            print(f"[!] File Not Found: {e}")

        except Exception as e:
            print(f"[!] Error saving: {e}")

        return False

    # Retrives user's credentails and check if the password hashe matches the provided password
    def read(self, p_user: str, path: Path) -> User:

        try:
            with open(path, 'r') as file:

                for line in file:

                   # Unpacking the list of strings into arguments
                   _user = User(*line.strip().split("|"))

                   if (_user.name == p_user):
                       return _user

        except Exception as e:
            print(f"[!] Error: {e}")
            return

        print("[!] User doesn't exist!")
        return

    # Registration
    def register(self, p_user: str, p_password: str) -> None:
        salt: int = Authenticator.gen_salt()
        salt_byte: bytes = salt.to_bytes(self.d_byte_size, byteorder='big')
        salt_hex: str = str(salt_byte.hex())
        passwd_hash: hex = Authenticator.hash_passwd(p_password.encode("utf-8"), salt_byte, self.d_iteration)

        # Storing user data
        Authenticator.user: User = User(p_user, salt_hex, passwd_hash, self.d_iteration, 0)
        success: bool = Authenticator.save(Authenticator.user, self.database)

        if (not(success)):
            print("[!] Registration Failed!")
            return

        print("[*] Registration Successful!")

        ui: UserInterface = UserInterface(self.key)

        if (Authenticator.user.clearance_level < 0):
            ui.dev_menu()
        else:
            ui.menu()

    # Authentication
    def login(self, p_user: str,  p_password: str) -> None:

        # Retriving user data from the database
        data: User = self.read(p_user, Authenticator.master_database if p_user == Authenticator.root_user else Authenticator.database)

        if (data):

            # Generating hash for the entered password
            passwd_hash = Authenticator.hash_passwd(p_password.encode("utf-8"), data.salt, data.iterations)

            # Comparing the current hashed password with the stored hash
            success = self.verify(passwd_hash, data.passwd_hash)

            # Fail
            if (not(success)):
                print("[!] Authentication Failed!")
                return

            # Setting the current user
            print("[*] Authentication Successful!")
            Authenticator.user = data

            time.sleep(0.5)
            ui: UserInterface = UserInterface(self.key)

            if (Authenticator.user.clearance_level < 0):
                ui.dev_menu()
            else:
                ui.menu()

        else:
            print("[!] User not found!")

class UserInterface:

    def __init__(self, p_key: bytes): 
        self.file_manager = FileManager(p_key)
        self.choice = None

    def dev_menu(self) -> None:
        self.clear()
        print(f"[1] Create a new file\n[2] Read a file\n[3] Append to a file\n[4] Delete a file\n[5] Set clearance level\n[6] Quit")
        choice = int(input(">>> "))
        self.clear()

        match (choice):

            # Create a new file
            case 1:
                self.create()
                self.dev_menu()

            # Read a file
            case 2:
                self.read()
                self.dev_menu()

            # Write to a file
            case 3:
                self.write()
                self.dev_menu()

            # Delete a file
            case 4:
                self.delete()
                self.dev_menu()

            # Set user's clearance level
            case 5:
                length = Authenticator.list_users()

                choice = int(input(">>> "))
                while (choice > length or choice < length):
                    choice = int(input(">>> "))

                self.clear()
                Authenticator.set_clearanace_level(choice)

                time.sleep(0.5)
                self.dev_menu()

            # Quit
            case _:
                return

    def menu(self):

        self.choice = None
        self.clear()
        print(f"[1] Create a new file\n[2] Read a file\n[3] Append to a file\n[4] Delete a file\n[5] Quit")
        self.choice = int(input(">>> "))
        self.clear()

        match (self.choice):

            # Create a new file
            case 1:
                self.create()
                self.menu()

            # Read a file
            case 2:
                self.read()
                self.menu()

            # Append to a file
            case 3:
                self.write()
                self.menu()

            # Delete a file
            case 4:
                self.delete()
                self.menu()

            case _:
                return

    # Clear the terminal
    def clear(self) -> None:
        print("\033[H\033[2J", end="")

    # Create a new file
    def create(self) -> None:
        print("[q] to return")
        file_name = input("Enter file name [q to return]: ")
        
        if (file_name != "q" and self.file_manager.create(file_name)):
            print("[*] File created!")
            time.sleep(1)

    # Read a file
    def read(self) -> None:
        if (self.file_manager.list_files()):
            self.choice = int(input(">>> "))
            self.file_manager.read(self.choice)
            self.choice = input("[q] to return ")

        else:
            print("[-] No files found!")
            time.sleep(1)

    # Write to a file
    def write(self) -> None:
        if (self.file_manager.list_files()):
            self.choice = int(input(">>> "))
            self.clear()
            self.file_manager.write(self.choice)

        else:
            print("[-] No files found!")
            time.sleep(1)

    # Delete a file
    def delete(self) -> None:
        if (self.file_manager.list_files()):
            print("[0] to return")
            self.choice = int(input(">>> "))

            if (self.choice == 0):
                self.menu()

            if (not(self.file_manager.delete(self.choice))):
                self.menu()

            print("[*] File Deleted!")

        else:
            print("[-] No Files found")
            time.sleep(1)

# Entrypoint
def main(args):

    # Initalizing Authenticator
    auth: Authenticator = Authenticator()

    match (args.command):

        case "login":
            auth.login(args.username, args.password)

        case "register":
            auth.register(args.username, args.password)

        case _:
            print("[!] No valid command has been passed")

    print("[*] Shutting down.")

if __name__ == "__main__":

    parser = argparse.ArgumentParser("Authentication Platform")
    sub_parser = parser.add_subparsers(dest="command", required=True)


    # Registration
    reg_args = sub_parser.add_parser("register")
    reg_args.add_argument("--username", "-u", required=True)
    reg_args.add_argument("--password", "-p", required=True)

    # Authentication
    auth_args = sub_parser.add_parser("login")
    auth_args.add_argument("--username", "-u", required=True)
    auth_args.add_argument("--password", "-p", required=True)

    args = parser.parse_args()
    main(args)