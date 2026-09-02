import hashlib
import argparse
import hmac
import secrets
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# Default values
FILENAME = "secrets.txt"
DIRECTORY = "data"
BIT_SIZE = 128
BYTE_SIZE = 16
ITERATION = 10000

class UserInterface:

    def __init__(self): 
        self.file_manager = FileManager()
        self.choice = None


    def menu(self):
        self.choice = None
        self.clear()
        print(f"[1] Create a new file\n[2] Read a file\n[3] Append to a file\n[4] Delete a file\n[5] Quit")
        self.choice = int(input(">>> "))
        self.clear()

        match (self.choice):

            # Create a new file
            case 1:
                print("[q] to return")
                file_name = input("Enter file name [q to return]: ")
                
                if (file_name != "q" and self.file_manager.create(file_name)):
                    print("[*] File created!")
                    time.sleep(1)

                self.menu()

            # Read a file
            case 2:
                if (self.file_manager.list_files()):
                    self.choice = int(input(">>> "))
                    self.file_manager.read(self.choice)
                    self.choice = input("[q] to return ")

                else:
                    print("[-] No files found!")
                    time.sleep(1)

                self.menu()

            # Append to a file
            case 3:
                if (self.file_manager.list_files()):
                    self.choice = int(input(">>> "))
                    self.clear()
                    self.file_manager.write(self.choice)

                else:
                    print("[-] No files found!")
                    time.sleep(1)

                self.menu()

            # Delete a file
            case 4:
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

                self.menu()

            case _:
                return

    # Clear the terminal
    def clear(self) -> None:
        print("\033[H\033[2J", end="")


class File:

    def __init__(self, name: str, cl: int) -> None:

        self._name = name
        self._cl = cl
        self._path = Path(DIRECTORY + "/" + self._name)

    # Create a new file
    def create(self,) -> bool:

        try:
            open(self._path, 'x')
            return True

        except FileExistsError as e:
            print(f"[!] File Error: {e}")

        return False

    # Reads the file
    def read(self) -> None:

        try:
            with open(self._path, 'r') as file:
                print(file.read())

        except FileNotFoundError as e:
            print(f"[!] File Error: {e}")

    def write(self) -> None:

        with open(self._path, "a") as file:
            data = input("[q to finish] >>> ")

            while (data != "q"):
                file.write(data + "\n")
                data = input("[q to finish] >>> ")

            print("[*] File saved!") 

        time.sleep(1)


    # Delets the file
    def delete(self) -> None:

        try:
            os.remove(self._path)

        except Exception as e:
            print(f"[!] Error: {e}")

class FileManager:

    # Keeps tracks of all the files
    stored_files = []

    def __init__(self):
        self._path = Path(DIRECTORY)

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
            print(f"[{idx+1}] {file._name}")

        return True

    def gen_key() -> bytes:
        pass

    def encrypt_doc() -> bytes:
        pass

    def decrypt_doc() -> bytes:
        pass

class Authenticator:


    # Generates a random saltAS
    def gen_salt(self, _bytes: int = BIT_SIZE) -> int:
        try:
            salt = secrets.randbits(_bytes)
            return salt
        
        except Exception as e:
            print(f"[!] Error generating salt: {e}")
            print("[*] Shuting down!")

        exit(1)


    # Geenerates a hash
    def hash_passwd(self, password: str, salt: bytes, iter: int = 10000) -> str:

        # Converting password from string to byte
        passwd_byte = password.encode("utf-8")

        try:
            # Hashing the password using the SHA256 hashing algorithm
            passwd_hash = hashlib.pbkdf2_hmac('sha256', passwd_byte, salt, iter)
            return passwd_hash.hex()

        except Exception as e:
            print(f"[!] Error hashing the password: {e}")
            print(f"[*] Shutting down.")

        exit(1)


    # Checks if the hashed passwords matches
    def verify(self, curr_hash: hex, stored_hash: hex) -> bool:
        return hmac.compare_digest(curr_hash, stored_hash)


    # Save the user's credentials to a file
    def save(self, user: str, salt: str, passwd_hash: str, iter: int) -> bool:
        try:
            with open(FILENAME, 'a') as file:

                # Saving the information to a text file
                data = f"{user}|{salt}|{passwd_hash}|{iter}\n"
                file.write(data)

        except Exception as e:
            print(f"Error Saving details: {e}")
            return False

        return True


    # Retrives user's credentails and check if the password hashe matches the provided password
    def read(self, user: str) -> tuple:
        try:
            with open(FILENAME, 'r') as file:

                for line in file:
                    _user, salt, _hash, iter = line.strip().split("|")

                    if (user == _user):
                        salt = bytes.fromhex(salt)
                        iter = int(iter)

                        return (salt, _hash, iter)

        except Exception as e:
            print(f"[!] Error: {e}")
            return False

        print("[!] User doesn't exist!")
        return False


    # Registration
    def register(self, user: str, password: str) -> bool:
        salt = self.gen_salt(BIT_SIZE)
        salt_byte = salt.to_bytes(BYTE_SIZE, byteorder='big')
        salt_hex = salt_byte.hex()

        passwd_hash = self.hash_passwd(password, salt_byte, ITERATION)

        success = self.save(user, salt_hex, passwd_hash, ITERATION)

        if (not(success)):
            print("[!] Registration Failed!")
            return False

        print("[*] Registration Successful!")
        return True


    # Authentication
    def login(self, user: str,  password: str) -> None:

        ui = UserInterface()

        data = self.read(user)

        if (data):
            passwd_hash = self.hash_passwd(password, data[0], data[2])

            success = self.verify(passwd_hash, data[1])

            if (not(success)):
                print("[!] Authentication Failed!")
                return

            print("[*] Authentication Successful!")

        time.sleep(1)
        ui.menu()


def main(args):

    auth = Authenticator()

    match (args.command):

        case "login":
            result = auth.login(args.username, args.password)

        case "register":
            result = auth.register(args.username, args.password)

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