from Crypto.PublicKey import RSA

def generar_par_claves(bits: int = 3072):
    # Generar par de claves RSA
    key = RSA.generate(bits)

    # Lo que hace es exportar clave pública en formato PEM (sin protección)
    with open("public_key.pem", "wb") as f:
        f.write(key.publickey().export_key("PEM"))

    # Esto exporta la clave privada en formato PEM protegida con passphrase, PKCS#8
    with open("private_key.pem", "wb") as f:
        f.write(key.export_key(
            "PEM",
            passphrase=b"lab04uvg",
            pkcs=8,
            protection="scryptAndAES128-CBC"
        ))

if __name__ == '__main__':
    generar_par_claves(3072)
    print("Claves generadas: private_key.pem y public_key.pem")