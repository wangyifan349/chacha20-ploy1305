"""
Complete Ed25519 digital signature example.
Purpose:
    1. Generate an identity key pair: private key / public key.
    2. Sign a message with the private key.
    3. Verify the signature with the public key.
    4. Show that verification fails if the message is modified.
    5. Save private/public keys as PEM files.
    6. Load private/public keys from PEM files.
Notes:
    - The private key must be kept secret.
    - The public key can be shared with verifiers.
    - Signing is not encryption: the message content is still visible.
    - A valid signature only proves that the corresponding private key signed the message.
    - Binding a public key to a real person requires an account system, certificate, trusted directory, or another trust mechanism.
"""

from __future__ import annotations
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key

PRIVATE_KEY_FILE = Path("alice_private_key.pem")
PUBLIC_KEY_FILE = Path("alice_public_key.pem")

def generate_key_pair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key_to_pem(private_key: Ed25519PrivateKey, file_path: Path) -> None:
    """Save an Ed25519 private key to a PEM file."""
    private_key_pem = private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    file_path.write_bytes(private_key_pem)

def save_public_key_to_pem(public_key: Ed25519PublicKey, file_path: Path) -> None:
    """Save an Ed25519 public key to a PEM file."""
    public_key_pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    file_path.write_bytes(public_key_pem)

def load_private_key_from_pem(file_path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    private_key_pem = file_path.read_bytes()
    private_key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Loaded private key is not an Ed25519 private key")
    return private_key

def load_public_key_from_pem(file_path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    public_key_pem = file_path.read_bytes()
    public_key = load_pem_public_key(public_key_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Loaded public key is not an Ed25519 public key")
    return public_key

def sign_message(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message with an Ed25519 private key."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    return private_key.sign(message)

def verify_signature(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False

def main() -> None:
    """Run a full Ed25519 signing and verification demo."""
    print("1. Generate Alice's Ed25519 key pair")
    alice_private_key, alice_public_key = generate_key_pair()
    print("Key pair generated\n")
    print("2. Save Alice's private and public keys to PEM files")
    save_private_key_to_pem(alice_private_key, PRIVATE_KEY_FILE)
    save_public_key_to_pem(alice_public_key, PUBLIC_KEY_FILE)
    print(f"Private key saved to: {PRIVATE_KEY_FILE}")
    print(f"Public key saved to: {PUBLIC_KEY_FILE}\n")
    print("3. Load keys back from PEM files")
    loaded_private_key = load_private_key_from_pem(PRIVATE_KEY_FILE)
    loaded_public_key = load_public_key_from_pem(PUBLIC_KEY_FILE)
    print("Keys loaded\n")
    print("4. Alice signs a message with her private key")
    message = b"user_id=alice&action=transfer&amount=100&currency=CNY"
    signature = sign_message(private_key=loaded_private_key, message=message)
    print("Original message:", message.decode("utf-8"))
    print("Signature hex:", signature.hex())
    print("Signature length:", len(signature), "bytes\n")
    print("5. A verifier checks the signature with Alice's public key")
    is_valid = verify_signature(public_key=loaded_public_key, message=message, signature=signature)
    print("Verification result:", is_valid)
    if is_valid:
        print("Conclusion: The message was signed by the private key corresponding to Alice's public key and was not modified.\n")
    else:
        print("Conclusion: Signature verification failed.\n")
    print("6. Simulate message tampering")
    tampered_message = b"user_id=alice&action=transfer&amount=999999&currency=CNY"
    tampered_valid = verify_signature(public_key=loaded_public_key, message=tampered_message, signature=signature)
    print("Tampered message:", tampered_message.decode("utf-8"))
    print("Tampered verification result:", tampered_valid)
    if not tampered_valid:
        print("Conclusion: The message was modified, so signature verification failed.\n")
    print("7. Simulate verifying Alice's signature with Bob's public key")
    bob_private_key, bob_public_key = generate_key_pair()
    wrong_key_valid = verify_signature(public_key=bob_public_key, message=message, signature=signature)
    print("Verification result with Bob's public key:", wrong_key_valid)
    if not wrong_key_valid:
        print("Conclusion: The wrong public key cannot verify Alice's signature.\n")
    print("Demo finished")

if __name__ == "__main__":
    main()
