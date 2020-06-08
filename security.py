'''
Practica 2 - Redes 2
File: security.py
Description: Archivo con funciones de
realizacion de firmas digitales,
encriptacion y desencriptacion
para autenticidad, confidencialidad
e integridad de los mensajes.
Authors:
    DanMat27
    AMP
'''
import sys
import os
import logging
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Cryptodome.Util.Padding import pad, unpad

# tamanio de la clave simetrica
sym_key_size = 32

################################################################
# FUNCTION: def generate_asimetric_key_from_user()
#
# DESCRIPTION: Funcion que genera la clave asimetrica
# mediante RSA de 2048 bits de longitud y la almacena en 
# un fichero .pem en la carpeta "Keys/"
#
# ARGS_IN: None
#
# ARGS_OUT: None
################################################################
def generate_asimetric_key_for_user():
    length = 2048

    private_key = RSA.generate(length)

    if not os.path.exists('./Keys/'):
        os.makedirs('./Keys/')

    with open("./Keys/privateKey.pem", "wb") as f:  
        f.write(private_key.exportKey(format='PEM'))  

    
################################################################
# FUNCTION: def get_private_asimetric_key_from_user()
#
# DESCRIPTION: Funcion que devuelve la clave privada de un
# usuario almacenada en local en la carpeta "Keys/"
#
# ARGS_IN: None
#
# ARGS_OUT: private - Clave privada
################################################################
def get_private_asimetric_key_from_user():
    f = open("./Keys/privateKey.pem",'r')
    private = RSA.importKey(f.read())
    f.close()
    return private


################################################################
# FUNCTION: def get_public_asimetric_key_from_user()
#
# DESCRIPTION: Funcion que devuelve la clave publica de un
# usuario almacenada la clave asimetrica en local en la 
# carpeta "Keys/"
#
# ARGS: None
#
# ARGS_OUT: public - Clave privada
################################################################
def get_public_asimetric_key_from_user():
    f = open("./Keys/privateKey.pem",'r')
    private = RSA.importKey(f.read())
    public = private.publickey()
    f.close()
    return public.exportKey(format='PEM')


################################################################
# FUNCTION: def get_hash_message(userFile)
#
# DESCRIPTION: Funcion que genera el hash del mensaje que el 
# usuario quiere enviar.
#
# ARGS: userFile - String con la direccion del fichero a enviar
#
# ARGS_OUT: hashMessage - Hash del mensaje
################################################################
def get_hash_message(userFile):
    try:
        # abrimos y hacemos el hash del mensaje a enviar
        hashMessage = SHA256.new()
        f = open(userFile, "rb")
        seg = f.read()
        hashMessage.update(seg)

        # cerramos el fichero
        f.close()

        return hashMessage
    # excepciones
    except Exception as e:
        print(e)
        return ""
    except:
        print("Ha ocurrido algun error.")
        return ""


################################################################
# FUNCTION: def get_signature_message(hashMessage)
#
# DESCRIPTION: Funcion que firma un mensaje con el hash del
# del mensaje y la clave privada del emisor.
#
# ARGS: hashMessage - Mensaje con hash a firmar
#
# ARGS_OUT: signatureMessage - Firma del mensaje
################################################################
def get_signature_message(hashMessage):
    # creamos la firma con la clave privada del emisor
    privateKey = get_private_asimetric_key_from_user()
    signer = PKCS1_v1_5.new(privateKey)

    # firmamos el mensaje
    signatureMessage = signer.sign(hashMessage)

    return signatureMessage


################################################################
# FUNCTION: def generate_message_with_sign(file,signatureMessage)
#
# DESCRIPTION: Funcion que concatena el mensaje firmado con el 
# mensaje.
#
# ARGS: file - Fichero a enviar
#       signatureMessage - Mensaje firmado
#
# ARGS_OUT: signMessage - Mensaje firmado mas mensaje
################################################################
def generate_message_with_sign(file,signatureMessage):
    # abrimos y leemos el fichero
    f = open(file, "rb")
    message = f.read()

    # concatenamos el fichero firmado con el fichero
    signMessage = signatureMessage + message

    # cerramos el fichero
    f.close()

    return signMessage


################################################################
# FUNCTION: def generate_symmetric_key()
#
# DESCRIPTION: Funcion que genera una clave simetrica.
#
# ARGS: none
#
# ARGS_OUT: symmetricKey - Clave simetrica
################################################################
def generate_symmetric_key():
    symmetricKey = Random.new().read(sym_key_size)

    return symmetricKey


################################################################
# FUNCTION: def generate_iv()
#
# DESCRIPTION: Funcion que genera un vector de inicializacion.
#
# ARGS: none
#
# ARGS_OUT: iv - Vector de inializacion
################################################################
def generate_iv():
    iv = Random.new().read(AES.block_size)

    return iv


################################################################
# FUNCTION: def encrypt_symmetric_message(iv,symmetricKey,signMessage)
#
# DESCRIPTION: Funcion que encripta con una clave simetrica
# y un iv un mensaje firmado.
#
# ARGS: iv - vector de inicializacion
#       symmetricKey - clave simetrica
#       signMessage - mensaje firmado
#
# ARGS_OUT: cipherMessage - Mensaje cifrado
################################################################
def encrypt_symmetric_message(iv, symmetricKey, signMessage):
    # creamos el objeto AES
    aes = AES.new(symmetricKey, AES.MODE_CBC, iv)

    # encriptamos el mensaje
    cipherMessage = aes.encrypt(pad(signMessage,AES.block_size))

    return cipherMessage


################################################################
# FUNCTION: def generate_envelope_message(symmetricKey,name)
#
# DESCRIPTION: Funcion que crea el sobre del mensaje.
#
# ARGS: symmetricKey - clave simetrica
#       publicKey - clave publica del receptor
#
# ARGS_OUT: envelopeMessage - Sobre del mensaje
################################################################
def generate_envelope_message(symmetricKey,publicKey):
    # conseguimos la clave publica del receptor
    publicKey = RSA.importKey(publicKey)

    # ciframos la clave simetrica con la clave publica del receptor
    cipher = PKCS1_OAEP.new(publicKey)
    envelopeMessage = cipher.encrypt(symmetricKey)

    return envelopeMessage

    
################################################################
# FUNCTION: def get_iv_from_message(file)
#
# DESCRIPTION: Funcion que saca el iv de un mensaje.
#
# ARGS: file - Fichero encriptado
#
# ARGS_OUT: iv - IV buscado
################################################################
def get_iv_from_message(file):
    # abrimos el fichero en modo lectura
    f = open(file, "rb")
    # leemos solo los 16 bytes del iv
    iv = f.read(16)

    f.close()

    return iv


################################################################
# FUNCTION: def get_envelope_message(file)
#
# DESCRIPTION: Funcion que saca el sobre de un mensaje.
#
# ARGS: file - Fichero encriptado
#
# ARGS_OUT: envelopeMessage - Sobre digital
################################################################
def get_envelope_message(file):
    # abrimos el fichero en modo lectura
    f = open(file, "rb")
    # leemos desde el fin del iv 32 bytes del sobre
    f.seek(16)
    envelopeMessage = f.read(256)

    f.close()

    return envelopeMessage


################################################################
# FUNCTION: def get_cipher_message(file)
#
# DESCRIPTION: Funcion que saca el mensaje encriptado y
# firmado de un mensaje enviado.
#
# ARGS: file - Fichero encriptado
#
# ARGS_OUT: cipherMessage - Mensaje cifrado
################################################################
def get_cipher_message(file):
    # abrimos el fichero en modo lectura
    f = open(file, "rb")
    # leemos el mensaje sin iv ni sobre
    f.seek(272)
    cipherMessage = f.read()

    f.close()

    return cipherMessage


################################################################
# FUNCTION: def decrypt_symmetric_key(envelopeMessage)
#
# DESCRIPTION: Funcion que desencripta la clave simetrica.
#
# ARGS: envelopeMessage - sobre digital
#
# ARGS_OUT: symmetricKey - Clave simetrica
################################################################
def decrypt_symmetric_key(envelopeMessage):
    # conseguimos la clave privada del receptor
    private = get_private_asimetric_key_from_user()
    # desencriptamos la clave simetrica con la clave privada del receptor
    cipher = PKCS1_OAEP.new(private)
    try:
        symmetricKey = cipher.decrypt(envelopeMessage)
    except Exception as e:
        logging.info("Este mensaje no es para ti.")
        return False

    return symmetricKey


################################################################
# FUNCTION: def decrypt_message(cipherMessage,symmetricKey,iv)
#
# DESCRIPTION: Funcion que desencripta el mensaje con 
# la clave simetrica.
#
# ARGS: cipherMessage - Mensaje cifrado
#       symmetricKey - Clave simetrica
#       iv - Vector de inicializacion
#
# ARGS_OUT: message - Mensaje desencriptado
################################################################
def decrypt_message(cipherMessage,symmetricKey,iv):
    aes = AES.new(symmetricKey, AES.MODE_CBC, iv)
    message = unpad(aes.decrypt(cipherMessage), AES.block_size)
    return message


################################################################
# FUNCTION: def is_author_the_author(message,publicKey)
#
# DESCRIPTION: Funcion que comprueba el emisor del mensaje
# y lo devuelve en caso correcto.
#
# ARGS: message - Mensaje descrifado
#       publicKey - Clave publica del emisor
#
# ARGS_OUT: text - Texto con el mensaje en caso correcto, texto
# vacio en caso contrario.
################################################################
def is_author_the_author(message,publicKey):
    # conseguimos la clave publica del emisor
    publicKey = RSA.importKey(publicKey)
    # verificamos la firma
    firma = message[:256]
    mensaje = message[256:]
    signer = PKCS1_v1_5.new(publicKey)
    sha = SHA256.new()
    sha.update(mensaje)
    verify = signer.verify(sha, firma)
    if verify == False:
        mensaje = ''
    return mensaje