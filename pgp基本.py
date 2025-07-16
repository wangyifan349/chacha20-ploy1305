import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


def generateKeyPair(userName, userEmail, passphrase=None, keyLength=2048):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, keyLength)
    userId = pgpy.PGPUID.new(userName, email=userEmail)
    key.add_uid(
        userId,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB]
    )
    if passphrase is not None:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


def saveKeyToFile(key, filePath):
    with open(filePath, "w", encoding="utf-8") as file:
        file.write(str(key))


def loadPublicKeyFromFile(filePath):
    """
    Load a public key from a file.
    Returns:
        pgpy.PGPKey: loaded public key object.
    """
    with open(filePath, "r", encoding="utf-8") as file:
        keyData = file.read()
    loadedKey, unusedBytes = pgpy.PGPKey.from_blob(keyData)
    if not loadedKey.is_public:
        raise ValueError("Loaded key is not a public key")
    return loadedKey


def loadPrivateKeyFromFile(filePath, passphrase=None):
    """
    Load a private key from a file. Unlocks with passphrase if key is protected.
    Returns:
        pgpy.PGPKey: loaded private key object.
    """
    with open(filePath, "r", encoding="utf-8") as file:
        keyData = file.read()
    loadedKey, unusedBytes = pgpy.PGPKey.from_blob(keyData)
    if loadedKey.is_protected:
        if passphrase is None:
            raise ValueError("Private key is protected, passphrase must be provided")
        loadedKey.unlock(passphrase)
    if loadedKey.is_public:
        raise ValueError("Loaded key is not a private key")
    return loadedKey


def encryptTextWithPublicKey(publicKey, plaintext, signingKey=None):
    message = pgpy.PGPMessage.new(plaintext)
    if signingKey is not None:
        encryptedMessage = publicKey.encrypt(message, sign=signingKey)
    else:
        encryptedMessage = publicKey.encrypt(message)
    return str(encryptedMessage)


def decryptTextWithPrivateKey(privateKey, encryptedText, verifyKey=None):
    message = pgpy.PGPMessage.from_blob(encryptedText)
    decryptedMessage = privateKey.decrypt(message)
    verification = None
    if verifyKey is not None and message.is_signed:
        verification = verifyKey.verify(decryptedMessage)
    return decryptedMessage.message, verification


def signTextWithPrivateKey(privateKey, plaintext):
    message = pgpy.PGPMessage.new(plaintext)
    signature = privateKey.sign(message)
    return str(signature)


def verifySignedTextWithPublicKey(publicKey, signedText):
    message = pgpy.PGPMessage.from_blob(signedText)
    verified = publicKey.verify(message)
    return verified


def encryptFileWithPublicKey(publicKey, inputFilePath, outputFilePath, signingKey=None):
    with open(inputFilePath, "r", encoding="utf-8") as file:
        plaintext = file.read()
    encryptedText = encryptTextWithPublicKey(publicKey, plaintext, signingKey)
    with open(outputFilePath, "w", encoding="utf-8") as file:
        file.write(encryptedText)


def decryptFileWithPrivateKey(privateKey, inputFilePath, outputFilePath, verifyKey=None):
    with open(inputFilePath, "r", encoding="utf-8") as file:
        encryptedText = file.read()
    plaintext, verification = decryptTextWithPrivateKey(privateKey, encryptedText, verifyKey)
    with open(outputFilePath, "w", encoding="utf-8") as file:
        file.write(plaintext)
    return verification


def signFileWithPrivateKey(privateKey, inputFilePath, outputFilePath):
    with open(inputFilePath, "r", encoding="utf-8") as file:
        plaintext = file.read()
    signature = signTextWithPrivateKey(privateKey, plaintext)
    with open(outputFilePath, "w", encoding="utf-8") as file:
        file.write(signature)


def verifyFileWithPublicKey(publicKey, signatureFilePath):
    with open(signatureFilePath, "r", encoding="utf-8") as file:
        signedText = file.read()
    verified = verifySignedTextWithPublicKey(publicKey, signedText)
    return verified


def main():
    print("PGP Demo - Options:")
    print("1. Generate key pair")
    print("2. Encrypt text")
    print("3. Decrypt text")
    print("4. Sign text")
    print("5. Verify signature")
    print("0. Quit")

    privateKey = None
    publicKey = None

    while True:
        choice = input("Choose option (0-5): ").strip()
        if choice == '0':
            print("Exiting program.")
            break
        elif choice == '1':
            userName = input("User name: ").strip()
            userEmail = input("User email: ").strip()
            passphraseInput = input("Passphrase (empty for none): ").strip()
            passphraseToUse = passphraseInput if passphraseInput != '' else None
            keyPair = generateKeyPair(userName, userEmail, passphraseToUse)
            saveKeyToFile(keyPair, "private_key.asc")
            saveKeyToFile(keyPair.pubkey, "public_key.asc")
            privateKey = keyPair
            publicKey = keyPair.pubkey
            print("Key pair generated and saved as private_key.asc and public_key.asc")
        elif choice == '2':
            if publicKey is None:
                try:
                    publicKey = loadPublicKeyFromFile("public_key.asc")
                except Exception as e:
                    print("Error loading public key:", e)
                    continue
            plaintext = input("Text to encrypt: ")
            try:
                encryptedText = encryptTextWithPublicKey(publicKey, plaintext)
                print("Encrypted message:\n", encryptedText)
            except Exception as e:
                print("Encryption failed:", e)
        elif choice == '3':
            if privateKey is None:
                passphraseInput = input("Passphrase for private key (empty if none): ").strip()
                passphraseToUse = passphraseInput if passphraseInput != '' else None
                try:
                    privateKey = loadPrivateKeyFromFile("private_key.asc", passphraseToUse)
                except Exception as e:
                    print("Error loading private key:", e)
                    continue
            encryptedText = input("Encrypted text to decrypt:\n")
            try:
                decryptedText, _verification = decryptTextWithPrivateKey(privateKey, encryptedText)
                print("Decrypted text:\n", decryptedText)
            except Exception as e:
                print("Decryption failed:", e)
        elif choice == '4':
            if privateKey is None:
                passphraseInput = input("Passphrase for private key (empty if none): ").strip()
                passphraseToUse = passphraseInput if passphraseInput != '' else None
                try:
                    privateKey = loadPrivateKeyFromFile("private_key.asc", passphraseToUse)
                except Exception as e:
                    print("Error loading private key:", e)
                    continue
            plaintext = input("Text to sign: ")
            try:
                signature = signTextWithPrivateKey(privateKey, plaintext)
                print("Signature:\n", signature)
            except Exception as e:
                print("Signing failed:", e)
        elif choice == '5':
            if publicKey is None:
                try:
                    publicKey = loadPublicKeyFromFile("public_key.asc")
                except Exception as e:
                    print("Error loading public key:", e)
                    continue
            signedText = input("Signed text to verify:\n")
            try:
                verified = verifySignedTextWithPublicKey(publicKey, signedText)
                if verified:
                    print("Signature verified successfully.")
                else:
                    print("Signature verification failed.")
            except Exception as e:
                print("Verification error:", e)
        else:
            print("Invalid choice, please enter 0-5.")


if __name__ == "__main__":
    main()
