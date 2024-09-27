import hashlib
from itertools import product

from Crypto.Hash import SHA256
from Crypto.Cipher import AES

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def read_keepass_header(filename):
    header = {}
    with open(filename, 'rb') as f:
        # Read the signature
        header['signature1'] = f.read(4)
        header['signature2'] = f.read(4)
        header['version'] = f.read(4)

        # Read header fields
        while True:
            field_id = f.read(1)
            field_size = int.from_bytes(f.read(2), byteorder='little')
            field_data = f.read(field_size)
            
            if field_id == b'\x00':  # End of header
                break
            header[field_id] = field_data
        
        header['data_start'] = f.tell()
    return header

def derive_key(password, master_seed, transform_seed, transform_rounds):
    
    #Hashing of the Password and the hashed password
    password_hash = SHA256.new(password.encode()).digest()
    credentials = SHA256.new(password_hash).digest()
    # print(f"Hashed password: {credentials.hex()}")
    
    #Transforming the Credentials
    transformed_credentials = credentials
    for _ in range(transform_rounds):
        cipher = AES.new(transform_seed, AES.MODE_ECB)
        transformed_credentials = cipher.encrypt(transformed_credentials)
    transformed_credentials = SHA256.new(transformed_credentials).digest()

    # print(f"Transformed credentials: {transformed_credentials.hex()}")
    
    #Hash the concatenation of master seed and the transformed credentials
    concatenated = master_seed + transformed_credentials
    final_key = SHA256.new(concatenated).digest()
    # print(f"Final key: {final_key.hex()}")
    return final_key

def try_decrypt(filename, key, iv, expected_start_bytes):
    with open(filename, 'rb') as f:
        f.seek(header['data_start'])  # Get the start of encrypted data
        encrypted_data = f.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    # print(f"Decrypted stream start: {decrypted_data[:32]}")
    # print(f"Stream start bytes: {expected_start_bytes}")
    # Check for valid decryption by comparing the stream start bytes
    return decrypted_data[:32] == expected_start_bytes

# Read the database file header
filename = 'Kaser.kdbx'
header = read_keepass_header(filename)

# Extract necessary components from header

master_seed = header[b'\x04']
transform_seed = header[b'\x05']
transform_rounds = int.from_bytes(header[b'\x06'], byteorder='little')
iv = header[b'\x07'][:16]
expected_start_bytes = header[b'\x09']

# print("Teansform: ", master_seed.hex())
# print("Teansform: ", transform_seed.hex())
# print("Teansform: ", transform_rounds)
# Brute-force passwords

for length in range(1, 5):  # 1 to 4 digits
    for digits in product('0123456789', repeat=length):
        password = ''.join(digits)
        print(f'Trying password: {password}')
        key = derive_key(password, master_seed, transform_seed, transform_rounds)
        if try_decrypt(filename, key, iv, expected_start_bytes):
            print(f'Success! The password is: {password}')
            break
    else:
        continue
    break
else:
    print('Failed to brute-force the password.')