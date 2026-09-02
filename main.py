import hashlib
import argparse
import hmac
import secrets

# Default values
FILENAME = "secrets.txt"
BIT_SIZE = 128
BYTE_SIZE = 16
ITERATION = 10000

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
            print("[!] Error retriving data: {e}")

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
    def login(self, user: str,  password: str) -> bool:
        data = self.read(user)

        if (data):
            passwd_hash = self.hash_passwd(password, data[0], data[2])
            print(passwd_hash)

            success = self.verify(passwd_hash, data[1])

            if (not(success)):
                print("[!] Authentication Failed!")
                return False

            print("[*] Authentication Successful!")
            return True

        return False


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