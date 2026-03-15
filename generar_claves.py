from Crypto.PublicKey import RSA

def generar_par_claves(bits: int = 3072):
    # TODO: implementar con RSA.generate()
    # Recordar: mínimo 2048 bits; recomendado 3072 para nuevo software
    pass

if __name__ == '__main__':
    generar_par_claves(3072)
    print("Claves generadas: private_key.pem y public_key.pem")