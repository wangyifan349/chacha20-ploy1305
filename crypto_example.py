from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Fernet
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.KDF import PBKDF2

key = RSA.generate(2048)

message = b"Hello, World!"
key_aes = b"my_secret_key"
cipher_aes = AES.new(key_aes, AES.MODE_ECB)
encrypted_data_aes = cipher_aes.encrypt(message)
print("AES Encryption:", encrypted_data_aes.hex())

encrypted_key_aes = PKCS1_OAEP.new(key).encrypt(key_aes, label=None)
print("RSA Encryption of AES Key:", encrypted_key_aes.hex())

hash = SHA256.new(message)
print("SHA256 Hash:", hash.hexdigest())

signature = PKCS1_v1_5.new(key).sign(hash)
print("RSA Signature:", signature.hex())

verified = PKCS1_v1_5.new(key).verify(hash, signature)
print("Signature Verification:", "Valid" if verified else "Invalid")

decrypted_key_aes = PKCS1_OAEP.new(key).decrypt(encrypted_key_aes, label=None)
print("RSA Decryption of AES Key:", decrypted_key_aes.hex())

decrypted_data_aes = cipher_aes.decrypt(encrypted_data_aes)
print("AES Decryption:", decrypted_data_aes.decode())

print("Decrypted Message:", decrypted_data_aes.decode())

key = get_random_bytes(16)
print("Random Key:", key.hex())

keypair = RSA.generate(2048)
print("Private Key:", keypair.export_key())
print("Public Key:", keypair.publickey().export_key())

encrypted_message = PKCS1_OAEP.new(keypair).encrypt(message)
print("Encrypted Message:", encrypted_message.hex())

decrypted_message = PKCS1_OAEP.new(keypair).decrypt(encrypted_message)
print("Decrypted Message:", decrypted_message.decode())

signature = PKCS1_v1_5.new(keypair).sign(hash)
print("RSA Signature:", signature.hex())

verified = PKCS1_v1_5.new(keypair).verify(hash, signature)
print("Signature Verification:", "Valid" if verified else "Invalid")

FERNET_KEY = get_random_bytes(32)
cipher = Fernet(FERNET_KEY)
encrypted_message = cipher.encrypt(message)
print("Encrypted Message:", encrypted_message.hex())

decrypted_message = cipher.decrypt(encrypted_message)
print("Decrypted Message:", decrypted_message.decode())

salt = get_random_bytes(16)
info = b"Information"
key = HKDF(salt, info, 32, algorithm="shake256")
print("Derived Key:", key.hex())

password = b"my_password"
salt = get_random_bytes(16)
key = PBKDF2(password, salt, 32)
print("Derived Key:", key.hex())
