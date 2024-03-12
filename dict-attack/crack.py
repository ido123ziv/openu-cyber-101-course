from Crypto.Hash import SHA256
import os
FOLDER_NAME=os.path.dirname(os.path.abspath(__file__))

PASSWORDS_FILE=f"{FOLDER_NAME}/passwords.txt"
PASSWORD_SHA="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"

def create_password_sha(password: str):
    """
    creates a sha256 from a given password
    :param password: string representing a password
    :return: a sha256 of the password
    """
    sh = SHA256.new()
    sh.update(bytes(password, encoding='utf-8'))
    return sh.hexdigest()

def read_known_passwords():
    with open(PASSWORDS_FILE, 'r') as pswd_file:
        passwords = pswd_file.readlines()
        for password in passwords:
            current_sha = create_password_sha(password.strip())
            # print(f"Trying: {password}\nsha: {current_sha}\n")
            if current_sha == PASSWORD_SHA:
                print("Cracked! the password is {}".format(password))

if __name__ == "__main__":
    print("Begin Cracking!")
    read_known_passwords()
