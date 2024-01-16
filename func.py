import pyaes, pbkdf2, binascii, os, secrets

def generate_key(password: str) -> (bytes, bytes):
    passwordSalt = os.urandom(16)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)

    return passwordSalt, key

def encrypt(plaintext: str, password: str) -> bytes:
    passwordSalt, key = generate_key(password)
    iv = secrets.randbits(256)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(plaintext)
    encrypted_text = binascii.hexlify(passwordSalt+iv.to_bytes(32, 'big')+ciphertext)
    
    return encrypted_text

def decrypt(encrypted_text: str, password: str) -> bytes:
    hex_encrypted_text = binascii.unhexlify(encrypted_text)
    extracted_salt = hex_encrypted_text[:16]
    decrypt_key = pbkdf2.PBKDF2(password, extracted_salt).read(32)

    extracted_iv = int.from_bytes(hex_encrypted_text[16:48], 'big')
    extracted_cipher = hex_encrypted_text[48:]

    aes = pyaes.AESModeOfOperationCTR(decrypt_key, pyaes.Counter(extracted_iv))
    decrypted_text = aes.decrypt(extracted_cipher)
    return decrypted_text