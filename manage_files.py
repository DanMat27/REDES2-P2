'''
Practica 2 - Redes 2
File: manage_files.py
Description: Archivo con funciones de
subida y descarga de archivos de una
Identidad especificada del servidor 
https://tfg.eps.uam.es:8080 y https://vega.ii.uam.es:8080.
Authors:
    DanMat27
    AMP
'''
import sys
import logging
from os import remove
from os import path
from identity import *
from security import *


################################################################
# FUNCTION: def list_files()
#
# DESCRIPTION: Funcion que lista los ficheros del usuario.
#
# ARGS: None
#
# ARGS_OUT: None
################################################################
def list_files():
    logging.info("Listando ficheros...")
    # listamos los ficheros
    url = 'https://vega.ii.uam.es:8080/api/files/list'
    header = {"Authorization":"Bearer " + token_aitor}
    response = requests.post(url, headers=header)
    if(response.ok):
        logging.info("OK")
        data = json.loads(response.content)
        logging.info("Numero de archivos: " + str(data["num_files"]))
        logging.info("Tus archivos son: ")
        i = 0
        for file in data["files_list"]:
            logging.info("[" + str(i) + "] " + str(file['fileID']))
            i += 1
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()


################################################################
# FUNCTION: def delete_files(fileID)
#
# DESCRIPTION: Funcion que elimina un fichero.
#
# ARGS: fileID - Id del fichero a eliminar
#
# ARGS_OUT: None
################################################################
def delete_files(fileID):
    logging.info("Eliminando fichero con ID " + fileID + "...")
    # listamos los ficheros
    url = 'https://vega.ii.uam.es:8080/api/files/delete'
    header = {"Authorization":"Bearer " + token_aitor, "Content-type":"application/json"}
    data = {"file_id":fileID}
    response = requests.post(url, headers=header, json=data)
    if(response.ok):
        logging.info("OK")
        data = json.loads(response.content)
        logging.info("El archivo con ID "+ str(data["file_id"]) + " se ha eliminado.")
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()


################################################################
# FUNCTION: def upload_file(file, destId)
#
# DESCRIPTION: Funcion que sube ficheros al servidor.
#
# ARGS: file - Fichero a subir
#       destId - Id del destinatario
#
# ARGS_OUT: None
################################################################
def upload_file(file, destId):
    logging.info("Solicitado envio de fichero a SecureBox...")
    # obtenemos la clave publica del destinatario
    publicKey = search_public_key(destId)
    # hacemos el hash del mensaje
    hashMessage = get_hash_message(file)
    # firmamos el mensaje
    logging.info("Firmando mensaje...OK")
    signatureMessage = get_signature_message(hashMessage)
    # generamos el iv
    iv = generate_iv()
    # generamos clave simetrica
    symmetricKey = generate_symmetric_key()
    # concatenamos el mensaje firmado con el mensaje
    signMessage = generate_message_with_sign(file, signatureMessage)
    # ciframos el mensaje con la clave simetrica, AES
    logging.info("Cifrando mensaje...OK")
    cipherMessage = encrypt_symmetric_message(iv,symmetricKey,signMessage)
    # creamos el sobre digital
    logging.info("Creando sobre digital...OK")
    envelopeMessage = generate_envelope_message(symmetricKey, publicKey)
    # juntamos iv, clave simetrica y mensaje
    logging.info("Enviando mensaje...OK")
    finalMessage = iv + envelopeMessage + cipherMessage

    if not os.path.exists('./Cifrados/'):
        os.makedirs('./Cifrados/')

    with open("./Cifrados/" + file, "wb") as f:  
        f.write(finalMessage)

    # subimos al servidor el mensaje encriptado
    logging.info("Subiendo archivo cifrado...")
    url = 'https://vega.ii.uam.es:8080/api/files/upload'
    header = {"Authorization":"Bearer " + token_mateo}
    data = {"ufile": open("Cifrados/" + file, 'rb')}
    response = requests.post(url, headers=header, files=data)
    if(response.ok):
        logging.info("OK")
        data = json.loads(response.content)
        logging.info("Archivo subido con ID: " + data['file_id'])
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()


################################################################
# FUNCTION: def download_file(file, sourceId)
#
# DESCRIPTION: Funcion que descarga ficheros desde el servidor.
#
# ARGS: file - Fichero a descargar
#       sourceId - Id del emisor
#
# ARGS_OUT: None
################################################################
def download_file(file, sourceId):
    logging.info("Descargando fichero de SecureBox...")
    # descargamos al servidor el mensaje encriptado
    logging.info("Descargando archivo cifrado...")
    url = 'https://vega.ii.uam.es:8080/api/files/download'
    header = {"Authorization":"Bearer " + token_mateo, "Content-type":"application/json"}
    data = {"file_id":file}
    response = requests.post(url, headers=header, json=data)
    if(response.ok):
        logging.info("OK")
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()

    if not os.path.exists('./Cifrados/'):
        os.makedirs('./Cifrados/')

    pathFile = "./Cifrados/" + file
    with open(pathFile, "wb") as f:
        #responseAux = response.content.encode()  
        f.write(response.content)
    
    # obtenemos la clave publica del emisor
    publicKey = search_public_key(sourceId)
    # sacamos el iv, clave simetrica (cifrada) y mensaje firmado y cifrado
    iv =  get_iv_from_message(pathFile)
    envelopeMessage = get_envelope_message(pathFile)
    cipherMessage = get_cipher_message(pathFile)
    # desencriptamos el sobre para hallar la clave simetrica
    symmetricKey = decrypt_symmetric_key(envelopeMessage)
    if symmetricKey == False:
        return
    # desencriptamos el mensaje
    message = decrypt_message(cipherMessage,symmetricKey,iv)
    # comprobamos el emisor del mensaje
    text = is_author_the_author(message,publicKey)
    if text != '':
        logging.info("Autenticidad: OK")
    else:
        logging.info("Autenticidad: ERROR")

    # escribimos mensaje en una carpeta
    if not os.path.exists('./Descifrados/'):
        os.makedirs('./Descifrados/')

    with open("./Descifrados/" + file, "wb") as f:  
        f.write(text)

    # eliminamos el fichero cifrado
    if path.exists("./Cifrados/" + file):
        remove("./Cifrados/" + file)


################################################################
# FUNCTION: def encrypt_file(file)
#
# DESCRIPTION: Funcion que encripta un fichero.
#
# ARGS: file - Fichero a cifrar
#
# ARGS_OUT: None
################################################################
def encrypt_file(file):
    logging.info("Encriptando fichero...")
    # abrimos y leemos el fichero
    f = open(file, "rb")
    message = f.read()
    # generamos el iv
    iv = generate_iv()
    # generamos clave simetrica
    symmetricKey = generate_symmetric_key()
    # ciframos el mensaje con la clave simetrica, AES
    logging.info("Cifrando mensaje...OK")
    cipherMessage = encrypt_symmetric_message(iv,symmetricKey,message)
    # mostramos el mensaje cifrado
    logging.info("MENSAJE CIFRADO")
    logging.info(cipherMessage)
    
    f.close()


################################################################
# FUNCTION: def sign_file(file)
#
# DESCRIPTION: Funcion que firma un fichero.
#
# ARGS: file - Fichero a firmar
#
# ARGS_OUT: None
################################################################
def sign_file(file):
    logging.info("Firmando fichero...")
    # hacemos el hash del mensaje
    hashMessage = get_hash_message(file)
    # firmamos el mensaje
    logging.info("Firmando mensaje...OK")
    signatureMessage = get_signature_message(hashMessage)
    # mostramos la firma
    logging.info("FIRMA")
    logging.info(signatureMessage)


################################################################
# FUNCTION: def enc_sign_file(file)
#
# DESCRIPTION: Funcion que encripta y firma un fichero.
#
# ARGS: file - Fichero a cifrar y firmar
#
# ARGS_OUT: None
################################################################
def enc_sign_file(file):
    logging.info("Cifrando y firmando mensaje...")
    # hacemos el hash del mensaje
    hashMessage = get_hash_message(file)
    # firmamos el mensaje
    logging.info("Firmando mensaje...OK")
    signatureMessage = get_signature_message(hashMessage)
    # generamos el iv
    iv = generate_iv()
    # generamos clave simetrica
    symmetricKey = generate_symmetric_key()
    # concatenamos el mensaje firmado con el mensaje
    signMessage = generate_message_with_sign(file, signatureMessage)
    # ciframos el mensaje con la clave simetrica, AES
    logging.info("Cifrando mensaje...OK")
    cipherMessage = encrypt_symmetric_message(iv,symmetricKey,signMessage)
    # mostramos el fichero firmado y cifrado
    logging.info("MENSAJE CIFRADO Y FIRMADO")
    logging.info(cipherMessage)