import os
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from generar_claves import generar_par_claves


def encrypt_document(document: bytes, recipient_public_key_pem: bytes) -> bytes:
    # a. Generar clave AES aleatoria de 256 bits
    aes_key = os.urandom(32)

    # b. Cifrar el documento con AES-256-GCM → nonce (12B) + tag (16B) + ciphertext
    nonce = os.urandom(12)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)

    # c. Cifrar la clave AES con la clave pública RSA usando PKCS1_OAEP
    rsa_key = RSA.import_key(recipient_public_key_pem)
    enc_aes_key = PKCS1_OAEP.new(rsa_key).encrypt(aes_key)

    # Empaquetar: [4B longitud enc_aes_key] + [enc_aes_key] + [12B nonce] + [16B tag] + [ciphertext]
    return struct.pack(">I", len(enc_aes_key)) + enc_aes_key + nonce + tag + ciphertext


def decrypt_document(pkg: bytes, recipient_private_key_pem: bytes, passphrase: bytes = b"lab04uvg") -> bytes:
    offset = 0

    # Desempaquetar la clave AES cifrada
    key_len = struct.unpack_from(">I", pkg, offset)[0]
    offset += 4
    enc_aes_key = pkg[offset:offset + key_len]
    offset += key_len

    # Extraer nonce (12B), tag (16B) y ciphertext
    nonce = pkg[offset:offset + 12]
    offset += 12
    tag = pkg[offset:offset + 16]
    offset += 16
    ciphertext = pkg[offset:]

    # Descifrar la clave AES con la clave privada RSA
    rsa_key = RSA.import_key(recipient_private_key_pem, passphrase=passphrase)
    aes_key = PKCS1_OAEP.new(rsa_key).decrypt(enc_aes_key)

    # Descifrar el documento con AES-GCM (verifica la integridad con el tag)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

if __name__ == '__main__':
    generar_par_claves(2048)

    with open("public_key.pem", "rb") as f: pub = f.read()
    with open("private_key.pem", "rb") as f: priv = f.read()

    # Generen un cifrado de un texto
    doc = b"Contrato de confidencialidad No. 2025-GT-001"
    pkg = encrypt_document(doc, pub)
    resultado = decrypt_document(pkg, priv)


    # Prueba con archivo de 1 MB (simula un contrato real)
    doc_grande = os.urandom(1024 * 1024)
    pkg2 = encrypt_document(doc_grande, pub)
    assert decrypt_document(pkg2, priv) == doc_grande
    print("Archivo 1 MB: OK")
