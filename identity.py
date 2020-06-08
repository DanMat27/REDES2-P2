'''
Practica 2 - Redes 2
File: identity.py
Description: Archivo con funciones de
creacion, borrado y busqueda de Identidades
en el servidor https://vega.ii.uam.es:8080 y
https://tfg.eps.uam.es:8080.
Authors:
    DanMat27
    AMP
'''
import sys
import logging
import requests
import json
from security import *

token_mateo = 'xxxxxxxxxxxxxx'
token_aitor = 'xxxxxxxxxxxxxx'

################################################################
# FUNCTION: def create_identity(newIdentity)
#
# DESCRIPTION: Funcion que registra el nombre, el email y 
# la clave publica (generada de una clave asimetrica con RSA) 
# de un usuario del que sabemos su token en el servidor y se 
# obtiene el ID del usuario como respuesta. Ademas, la clave
# asimetrica privada del usuario se encuentra en la carpeta 
# "Keys/" para ser utilizada en otras acciones.
#
# ARGS_IN: newIdentity - Lista con el nombre y el email del
#       usuario
#
# ARGS_OUT: None
################################################################
def create_identity(newIdentity):
    name = newIdentity[0]
    email = newIdentity[1]
    logging.info("Generando par de claves RSA de 2048 bits...")
    url = 'https://vega.ii.uam.es:8080/api/users/register'
    if(email == 'daniel.mateom@estudiante.uam.es'):
        header = {"Authorization":"Bearer " + token_mateo, "Content-type":"application/json"}
    else:
        header = {"Authorization":"Bearer " + token_aitor, "Content-type":"application/json"}
    generate_asimetric_key_for_user()
    public = get_public_asimetric_key_from_user()
    data = {"nombre":name, "email":email, 'publicKey':public}
    response = requests.post(url, headers=header, json=data)
    if(response.ok):
        data = json.loads(response.content)
        logging.info("OK")
        logging.info("Usuario con nombre: " + name + " y email: " + email + " registrado " +
        "exitosamente en el servidor con ID:" + data['userID'])
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()


################################################################
# FUNCTION: def delete_identity(identity)
#
# DESCRIPTION: Funcion que borra los datos de un usuario 
# del que sabemos su token del servidor. (Tras esto, hay que
# volver a pedir un nuevo token al servidor.)
#
# ARGS_IN: identity - ID del usuario a borrar
#
# ARGS_OUT: None
################################################################
def delete_identity(identity):
    logging.info("Solicitando borrado de la identidad #" + identity + "...")
    url = 'https://vega.ii.uam.es:8080/api/users/delete'
    if(identity == '380571'):
        header = {"Authorization":"Bearer " + token_mateo, "Content-type":"application/json"}
    else:
        header = {"Authorization":"Bearer " + token_aitor, "Content-type":"application/json"}
    data = {"userID":identity}
    response = requests.post(url, headers=header, json=data)
    if(response.ok):
        logging.info("OK")
        data = json.loads(response.content)
        logging.info("Identidad con ID:" + str(data['userID']) + " borrada correctamente")
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()


################################################################
# FUNCTION: def search_identity(name)
#
# DESCRIPTION: Funcion que busca en el servidor un usuario
# con el nombre indicado y devuelve todos los usuarios que
# se llamen igual con su correspondiente informacion de 
# usuario.
#
# ARGS_IN: name - Nombre del usuario
#
# ARGS_OUT: None
################################################################
def search_identity(name):
    logging.info("Buscando usuario '" + name + "' en el servidor...")
    url = 'https://vega.ii.uam.es:8080/api/users/search'
    header = {"Authorization":"Bearer " + token_mateo, "Content-type":"application/json"}
    data = {"data_search":name}
    response = requests.post(url, headers=header, json=data)
    if(response.ok):
        logging.info("OK")
        data = json.loads(response.content)
        logging.info(str(len(data)) + " usuarios encontrados:")
        i = 0
        for user in data:
            logging.info("[" + str(i) + "] " + str(user['nombre']) + ", " + str(user['email']) + ", ID:" + str(user['userID']))
            i += 1
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()


################################################################
# FUNCTION: def search_public_key(id)
#
# DESCRIPTION: Funcion que busca en el servidor la clave
# publica de un usuario introduciendo el identificador 
# de ese propio usuario.
#
# ARGS_IN: id - Identificador del usuario
#
# ARGS_OUT: publicKey - Clave publica del usuario o false en
# en caso de error.
################################################################
def search_public_key(id):
    logging.info("Buscando clave publica de usuario con id '" + id + "' en el servidor...")
    url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
    header = {"Authorization":"Bearer " + token_aitor, "Content-type":"application/json"}
    data = {"userID":id}
    response = requests.post(url, headers=header, json=data)
    if(response.ok):
        logging.info("OK")
        data = json.loads(response.content)
        logging.info("ID: " + str(data['userID']) + "\nPublic Key: \n" + str(data['publicKey']))
        return data['publicKey']
    else:
        logging.error("Error en la peticion POST")
        response.raise_for_status()
        return False
