from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import tempfile
import os
file_path = ".\\password.txt"

try:
    with open(file_path, 'r') as file:
        print("Password file exists.")
        data = file.readlines()
except:
    print("Password file does not exist.")
    try:
        with open(".\\backup.txt", 'r') as file:
            print("Backup file exists.")
            data = file.readlines()
            with open(".\\password.txt", 'w') as file:
                file.writelines(data)
    except:
        print("Backup file does not exist.")
        with open('.\\backup.txt', 'w') as file:
            file.writelines([])
        with open('.\\password.txt', 'w') as file:
            file.writelines([])
try:
    with open('.\\login.txt', 'r') as file:
        print("Login file exists.")
        data = file.readlines()
    if data==[]:
        print("Login file is empty.")
        with open('.\\password.txt', 'w') as file:
            file.writelines([])
except:
    print("Login file does not exist. Creating new login file.")
    data=[]
    with open('.\\login.txt', 'w') as file:
        file.writelines(data)
        with open('.\\password.txt', 'w') as file:
            file.writelines([])
        

def read_key():
    with open('.\\login.txt', 'r') as file:
        data = file.readlines()
    if len(data) < 2:
        return None, None
    parts = data[1].strip().split('|')
    if len(parts) == 2:
        salt = bytes.fromhex(parts[0])
        key = bytes.fromhex(parts[1])
        return salt, key
    else:
        # Legacy format (just key hash), return None for salt
        return None, bytes.fromhex(data[1].strip())

def encrypt_message(message):
    salt, key = read_key()
    if key is None:
        return None, None, None
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        nonce = cipher.nonce
        return ciphertext, nonce, tag
    except (ValueError, KeyError) as e:
        print(f"An error occurred: {e}")
        return None, None, None

def encrypt_site_name(site):
    """Encrypt site name for metadata protection"""
    salt, key = read_key()
    if key is None:
        return None, None, None
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(site.encode('utf-8'))
        nonce = cipher.nonce
        return ciphertext, nonce, tag
    except (ValueError, KeyError) as e:
        print(f"An error occurred: {e}")
        return None, None, None
def decrypt_message_og(site):
    salt, key = read_key()
    if key is None:
        return "Error: No key found"
    try:
        ciphertext, nonce, tag = must_for_decrypt_og(site)
        if ciphertext is None:
            return "Site not found"
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        plaintext = plaintext_bytes.decode("utf-8")
        return plaintext
    except (ValueError, KeyError) as e:
        print(f"An error occurred: {e}")
        return "Decryption failed"

def decrypt_site_name(site_cipher, nonce, tag):
    """Decrypt site name"""
    salt, key = read_key()
    if key is None:
        return None
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(site_cipher, tag)
        return plaintext_bytes.decode("utf-8")
    except (ValueError, KeyError) as e:
        print(f"An error occurred: {e}")
        return None

def must_for_decrypt_og(site):
    with open(file_path, 'r') as file:
        data = file.readlines()
    for line in data:
        words = line.split()
        if len(words) >= 6:
            # New format: site_cipher site_nonce site_tag pass_cipher pass_nonce pass_tag
            site_cipher = bytes.fromhex(words[0])
            site_nonce = bytes.fromhex(words[1])
            site_tag = bytes.fromhex(words[2])
            decrypted_site = decrypt_site_name(site_cipher, site_nonce, site_tag)
            if decrypted_site == site:
                ciphertext = bytes.fromhex(words[3])
                nonce = bytes.fromhex(words[4])
                tag = bytes.fromhex(words[5])
                return ciphertext, nonce, tag
        elif len(words) == 3:
            # Legacy format: site_hex pass_cipher iv (CBC mode)
            if site == bytes.fromhex(words[0]).decode('utf-8'):
                # Convert old CBC to GCM on read
                return None, None, None
    return None, None, None
# Get the key string from the user
def check_key(user_input):
    key_string = user_input
    with open(".\\login.txt", 'r') as file:
        data = file.readlines()
    if len(data) < 2:
        return False
    
    parts = data[1].strip().split('|')
    if len(parts) == 2:
        # New format with PBKDF2
        salt = bytes.fromhex(parts[0])
        stored_key = bytes.fromhex(parts[1])
        # Derive key from user input with stored salt
        derived_key = PBKDF2(key_string.encode(), salt, dkLen=32, count=100000)
        return derived_key == stored_key
    else:
        # Legacy format (SHA256 only)
        key = SHA256.new(key_string.encode()).digest()
        stored_key = data[1].strip()
        return key.hex() == stored_key

def get_key(user_input, salt=None):
    key_string = user_input
    if salt is None:
        salt = get_random_bytes(16)
    # Use PBKDF2 for proper key derivation
    key = PBKDF2(key_string.encode(), salt, dkLen=32, count=100000)
    return key, salt

def get_sites():
    with open(file_path, 'r') as file:
        data = file.readlines()
    sites = []
    for line in data:
        words = line.split()
        if len(words) >= 6:
            # New format with encrypted site names
            site_cipher = bytes.fromhex(words[0])
            site_nonce = bytes.fromhex(words[1])
            site_tag = bytes.fromhex(words[2])
            decrypted_site = decrypt_site_name(site_cipher, site_nonce, site_tag)
            if decrypted_site:
                sites.append(decrypted_site)
        elif len(words) == 3:
            # Legacy format with plain hex site names
            try:
                sites.append(bytes.fromhex(words[0]).decode('utf-8'))
            except:
                pass
    return sites

def new_key(user_input):
    key_string=user_input
    # Hash the key string to create a 256-bit key
    key = SHA256.new(key_string.encode()).digest()
    data=['logged_in'+'\n',key.hex()]
    with open('.\\login.txt', 'w') as file:
        file.writelines(data)

def write_file_atomic(filepath, data):
    """Atomically write data to file to prevent corruption"""
    dir_path = os.path.dirname(filepath) or '.'
    with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_path, encoding='utf-8') as tmp:
        if isinstance(data, list):
            tmp.writelines(data)
        else:
            tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
    try:
        os.replace(tmp.name, filepath)
    except Exception as e:
        os.unlink(tmp.name)
        raise e

def backup_passwords():
    with open(file_path, 'r') as file:
        data = file.readlines()
    # Atomic write to backup
    write_file_atomic(".\\backup.txt", data)

def choice_1(site, password):
    # Encrypt both site name and password
    site_cipher, site_nonce, site_tag = encrypt_site_name(site)
    pass_cipher, pass_nonce, pass_tag = encrypt_message(password)
    
    if site_cipher is None or pass_cipher is None:
        return None, None
    
    with open(file_path, 'r') as file:
        data = file.readlines()
    
    if data == []:
        new_entry = f"{site_cipher.hex()} {site_nonce.hex()} {site_tag.hex()} {pass_cipher.hex()} {pass_nonce.hex()} {pass_tag.hex()}\n"
        data.append(new_entry)
    else:
        check = False
        existing_index = -1
        
        # Check if site already exists
        for i, line in enumerate(data):
            words = line.split()
            if len(words) >= 6:
                existing_site_cipher = bytes.fromhex(words[0])
                existing_site_nonce = bytes.fromhex(words[1])
                existing_site_tag = bytes.fromhex(words[2])
                decrypted = decrypt_site_name(existing_site_cipher, existing_site_nonce, existing_site_tag)
                if decrypted == site:
                    check = True
                    existing_index = i
                    break
            elif len(words) == 3:
                # Legacy format
                try:
                    if bytes.fromhex(words[0]).decode('utf-8') == site:
                        check = True
                        existing_index = i
                        break
                except:
                    pass
        
        if check:
            data_no = [line for line in data]
            data_yes = [line for i, line in enumerate(data) if i != existing_index]
            new_entry = f"{site_cipher.hex()} {site_nonce.hex()} {site_tag.hex()} {pass_cipher.hex()} {pass_nonce.hex()} {pass_tag.hex()}\n"
            data_yes.append(new_entry)
            return data_no, data_yes
        else:
            new_entry = f"{site_cipher.hex()} {site_nonce.hex()} {site_tag.hex()} {pass_cipher.hex()} {pass_nonce.hex()} {pass_tag.hex()}\n"
            data.append(new_entry)
    
    write_file_atomic(file_path, data)
    return None, None

def encrypt_with_new_key(new_key_string):
    # First decrypt all existing passwords with old key
    with open(file_path, 'r') as file:
        data = file.readlines()
    
    decrypted_data = []
    for line in data:
        words = line.split()
        if len(words) >= 6:
            site_cipher = bytes.fromhex(words[0])
            site_nonce = bytes.fromhex(words[1])
            site_tag = bytes.fromhex(words[2])
            site = decrypt_site_name(site_cipher, site_nonce, site_tag)
            if site:
                password = decrypt_message_og(site)
                if password and not password.startswith("Error") and not password.startswith("Decryption"):
                    decrypted_data.append((site, password))
        elif len(words) == 3:
            # Legacy format
            try:
                site = bytes.fromhex(words[0]).decode('utf-8')
                password = decrypt_message_og(site)
                if password and password != "Wrong key.":
                    decrypted_data.append((site, password))
            except:
                pass
    
    # Generate new salt and key
    salt = get_random_bytes(16)
    new_key = PBKDF2(new_key_string.encode(), salt, dkLen=32, count=100000)
    
    # Write new login file
    login_data = ['logged_in\n', f'{salt.hex()}|{new_key.hex()}']
    write_file_atomic(".\\login.txt", login_data)
    
    # Re-encrypt all passwords with new key
    new_passwords = []
    for site, password in decrypted_data:
        site_cipher, site_nonce, site_tag = encrypt_site_name(site)
        pass_cipher, pass_nonce, pass_tag = encrypt_message(password)
        if site_cipher and pass_cipher:
            new_entry = f"{site_cipher.hex()} {site_nonce.hex()} {site_tag.hex()} {pass_cipher.hex()} {pass_nonce.hex()} {pass_tag.hex()}\n"
            new_passwords.append(new_entry)
    
    write_file_atomic(file_path, new_passwords)

def main_function(key):
    print("1. Encrypt")
    print("2. Decrypt")
    choice=input()
    while(choice!='0'):
        with open(file_path, 'r') as file:
            data = file.readlines()
        if(choice=='1'):
            print("Enter site: ")
            site=input()
            password=input()
            ciphertext,iv=encrypt_message(password,key)
            if(data==[]):
                data.append(site.hex()+" "+ciphertext.hex()+" "+iv.hex()+"\n")
            else:
                check=False
                for line in data:
                    if(site.hex() in line):
                        check=True
                if(check):
                        print("Site already exists. Overwrite? (y/n)")
                        choice=input()
                        if(choice=='n'):
                            data = [line for line in data]
                        else:
                            data = [line for line in data if site.hex() not in line]
                            data.append(site.hex()+" "+ciphertext.hex()+" "+iv.hex()+"\n")
                else:
                    data.append(site.hex()+" "+ciphertext.hex()+" "+iv.hex()+"\n")        
            with open(file_path, 'w') as file:
                file.writelines(data)
        elif(choice=='2'):
            print("Enter site:")
            site=input()
            for line in data:
                words=line.split()
                if(site.hex()==words[0]):
                    ciphertext=bytes.fromhex(words[1])
                    iv=bytes.fromhex(words[2])
                    break
            plaintext=decrypt_message_og(key,site)
            print(plaintext)
        print("1. Encrypt")
        print("2. Decrypt")
        choice=input()
    
