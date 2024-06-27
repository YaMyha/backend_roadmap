import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def use_md5():
    def md5_hash(data):
        md5 = hashlib.md5()
        md5.update(data.encode('utf-8'))
        return md5.hexdigest()

    data = "Hello, World!"
    hashed_data = md5_hash(data)
    print(f"MD5 Hash: {hashed_data}")


def use_sha256():
    def sha256_hash(data):
        sha256 = hashlib.sha256()
        sha256.update(data.encode('utf-8'))
        return sha256.hexdigest()

    data = "Hello, World!"
    hashed_data = sha256_hash(data)
    print(f"SHA-256 Hash: {hashed_data}")


def use_rsa():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    def export_keys(private_key, public_key):
        # Экспорт закрытого ключа в PEM формате
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Экспорт открытого ключа в PEM формате
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print(f"Private Key:\n{private_pem.decode()}")
        print(f"Public Key:\n{public_pem.decode()}")

    export_keys(private_key, public_key)

    # Шифрование данных
    message = b"Hello, RSA!"
    # OAEP is used for encrypting data using asymmetric algorithms such as RSA. It protects against attacks exploiting
    # ciphertext predictability and padding oracle vulnerabilities.
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Encrypted Message: {encrypted_message}")

    # Расшифрование данных
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"Decrypted Message: {decrypted_message.decode()}")


use_rsa()
