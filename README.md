# Criptografia RSA — Plataforma de Transferencia de Documentos Legales

Ejercicio académico de la Universidad del Valle de Guatemala (Cifrados de Información).
Implementa un sistema de cifrado híbrido RSA-OAEP + AES-256-GCM para transferir documentos
confidenciales garantizando que solo el destinatario pueda leerlos.

---

## Descripción del Proyecto

El sistema simula una firma de abogados con oficinas en Guatemala City, Miami y Madrid que
necesita transferir contratos, acuerdos de confidencialidad y datos personales de forma segura.

### Arquitectura de cifrado híbrido

```
Documento  ──AES-256-GCM──►  Ciphertext + Tag + Nonce
Clave AES  ──RSA-OAEP──────►  Clave AES cifrada
                                    │
                              Paquete final
```

RSA protege la clave AES (pequeño secreto) y AES cifra el documento real (sin límite de tamaño).

---

## Instalación

```bash
pip install pycryptodome
```

> **Nota:** Usar `pycryptodome`, no `pycrypto` (abandonado). Ambos exponen el mismo namespace
> `Crypto.*` pero `pycryptodome` está mantenido activamente.

---

## Estructura del proyecto

```
.
├── generar_claves.py   # Genera par de claves RSA y las guarda en PEM
├── rsa_OAEP.py         # Cifrado/descifrado directo con RSA-OAEP
├── rsa_AES_GCM.py      # Cifrado híbrido RSA-OAEP + AES-256-GCM
├── README.md
└── Ejercicio RSA.pdf
```

---

## Instrucciones de Uso

Ejecutar los scripts en orden:

### 1. Generar claves RSA

```bash
python generar_claves.py
```

Genera dos archivos:
- `public_key.pem` — clave pública (puede compartirse libremente)
- `private_key.pem` — clave privada protegida con passphrase `lab04uvg`

### 2. Cifrado y descifrado directo con RSA-OAEP

```bash
python rsa_OAEP.py
```

Cifra y descifra un mensaje corto. También demuestra que cifrar el mismo mensaje dos veces
produce ciphertexts distintos.

### 3. Cifrado híbrido RSA-OAEP + AES-256-GCM

```bash
python rsa_AES_GCM.py
```

Cifra y descifra un documento de texto y un archivo de 1 MB generado aleatoriamente.

---

## Ejemplos de Ejecución

### `python generar_claves.py`
```
Claves generadas: private_key.pem y public_key.pem
```

### `python rsa_OAEP.py`
```
Original  : b'El mensaje sera la clave secreta de AES'
Cifrado   : 3a7f2c1d8e...
Descifrado: b'El mensaje sera la clave secreta de AES'

c1 == c2: False
```

### `python rsa_AES_GCM.py`
```
Archivo 1 MB: OK
```

---

## Preguntas de Análisis

### 1. ¿Por qué no cifrar el documento directamente con RSA?

RSA tiene dos limitaciones fundamentales que lo hacen inadecuado para cifrar documentos completos:

1. **Límite de tamaño del mensaje:** RSA solo puede cifrar un bloque de datos menor que el módulo `n`.
   Con RSA-2048 y OAEP-SHA256, el máximo es `256 - 2*32 - 2 = 190 bytes`. Un contrato PDF
   puede superar fácilmente varios megabytes.

2. **Rendimiento:** RSA es hasta 1000× más lento que AES para cifrar datos. AES opera en hardware
   (AES-NI) y procesa gigabytes por segundo; RSA requiere exponenciación modular con números
   de 2048+ bits.

La solución es el **cifrado híbrido**: AES cifra el documento (eficiente, sin límite de tamaño),
RSA cifra solo la clave AES de 32 bytes (dentro del límite). El destinatario descifra primero la
clave AES con su clave privada RSA y luego descifra el documento con AES.

---

### 2. ¿Qué información contiene un archivo .pem?

Un archivo PEM (_Privacy-Enhanced Mail_) es un contenedor de datos criptográficos codificados
en **Base64**, delimitado por cabeceras tipo:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

El contenido decodificado es una estructura **ASN.1 DER** (_Distinguished Encoding Rules_) que
para una clave pública RSA incluye:

- **OID del algoritmo** (`1.2.840.113549.1.1.1` = rsaEncryption)
- **Módulo `n`** (producto de los dos primos `p × q`), de 256 bytes para RSA-2048
- **Exponente público `e`** (normalmente `65537 = 0x10001`)

La clave privada cifrada contiene adicionalmente: los primos `p` y `q`, el exponente privado `d`,
y los coeficientes de optimización CRT (`dp`, `dq`, `qInv`), todo protegido por el esquema de
cifrado simétrico especificado en la cabecera PKCS#8 (en este caso `scryptAndAES128-CBC`).

---

### 3. ¿Por qué cifrar el mismo mensaje dos veces con RSA-OAEP produce resultados distintos?

OAEP (_Optimal Asymmetric Encryption Padding_) es un esquema de **padding probabilístico**.
Antes de aplicar la exponenciación RSA, el esquema:

1. Genera una **semilla aleatoria `r`** de 32 bytes (longitud del hash SHA-256)
2. Calcula `maskedSeed = r XOR MGF(mensaje_padded)`
3. Calcula `maskedDB = mensaje_padded XOR MGF(r)`
4. Concatena `maskedSeed || maskedDB` → este bloque se eleva a `e mod n`

Como `r` es distinto en cada cifrado, el bloque de entrada a RSA es diferente aunque el mensaje
sea idéntico, produciendo un ciphertext distinto cada vez.

Esta propiedad se llama **cifrado probabilístico** (_IND-CPA security_): un atacante que observa
dos ciphertexts del mismo mensaje no puede distinguirlos ni confirmar que son iguales.
PKCS#1 v1.5 carece de esta propiedad (padding determinista) y es vulnerable a ataques de
oráculo de padding (Bleichenbacher 1998), razón por la que OAEP lo reemplazó.

---

## Seguridad

| Elemento | Algoritmo | Parámetros |
|---|---|---|
| Intercambio de clave | RSA-OAEP | 2048 / 3072 bits, SHA-256 |
| Cifrado de documento | AES-GCM | 256 bits, nonce 96 bits |
| Autenticación | GCM Tag | 128 bits |
| Protección clave privada | scrypt + AES-128-CBC | PKCS#8 |
