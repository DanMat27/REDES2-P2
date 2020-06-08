"""
Practica 2 - Redes 2
File: securebox_client.py
Description: Fichero que actua como cliente de comandos
donde se pueden crear, buscar o eliminar identidades del
servidor https://vega.ii.uam.es:8080/.
Tambien se puede subir archivos a una identidad elegida
o descargar archivos de una identidad elegida.
Authors:
    DanMat27
    AMP
"""
import sys
import argparse
from argparse import RawTextHelpFormatter
import logging
from identity import *
from manage_files import *

if __name__ == "__main__":
    global args

    # Opciones por argumento (args)
    parser = argparse.ArgumentParser(description="Gestion de identidades: Crea (--create_id NOMBRE EMAIL), busca (--search_id NOMBRE), " + 
    "consigue la clave publica de un usuario (--get_public_key ID) o borra una identidad (--delete_id ID).\nOtras acciones:" + 
    " Subida de archivos (--upload FILE --dest_id ID), descarga de archivos (--download FILE_ID --source_id ID)," +
    " listado de archivos (--list_files), borrado de archivos (delete_file FILE_ID)," + 
    " encriptar archivos (--encrypt FILE), firmar archivos (--sign FILE) o encriptar y firmar archivos (--enc_sign FILE)." +
    "\nSe ha de seleccionar solo una opcion para ejecutar una accion en concreto.", 
    formatter_class=RawTextHelpFormatter)
    parser.add_argument("--create_id", dest="createId", nargs='*', default=False, help="Opcion de creacion de una nueva identidad")
    parser.add_argument("--search_id", dest="searchId", default=False, help="Opcion de busqueda de una identidad")
    parser.add_argument("--get_public_key", dest="getPublicKey", default=False, help="Opcion de busqueda de una clave publica")
    parser.add_argument("--delete_id", dest="deleteId", default=False, help="Opcion de borrado de una identidad")
    parser.add_argument("--list_files", dest="listF", action="store_true", default=False, help="Opcion de listado de archivos")
    parser.add_argument("--delete_file", dest="deleteF", default=False, help="Opcion de borrado de archivos")
    parser.add_argument("--upload", dest="upload", default=False, help="Opcion de subida de archivos para una identidad del servidor")
    parser.add_argument("--dest_id", dest="destId", default=False, help="Requerida para --upload. Identidad destino.")
    parser.add_argument("--download", dest="download", default=False, help="Opcion de descarga de archivos de una identidad del servidor")
    parser.add_argument("--source_id", dest="sourceId", default=False, help="Requerida para --download. Identidad fuente.")
    parser.add_argument("--encrypt", dest="encrypt", default=False, help="Opcion de encriptar archivos.")
    parser.add_argument("--sign", dest="sign", default=False, help="Opcion de firmar archivos.")
    parser.add_argument("--enc_sign", dest="enc_sign", default=False, help="Opcion de encriptar y firmar archivos.")
    parser.add_argument("--debug", dest="debug", default=False, action="store_true", help="Activar mensajes de Debug")
    args = parser.parse_args() 

    # Opcion de debug
    if args.debug:
        logging.basicConfig(level = logging.DEBUG, format = "[%(asctime)s %(levelname)s]\t%(message)s")
    else:
        logging.basicConfig(level = logging.INFO, format = "%(message)s")

    # Eleccion del usuario de accion a ejecutar
    # Crear ID
    if (args.createId != False):
        logging.info("Opcion elegida: Creacion de identidad.")
        if(len(args.createId) != 2):
            logging.error("No se han especificado bien los argumentos de --create_id")
            sys.exit(-1)
        create_identity(args.createId)

    # Buscar ID
    elif (args.searchId != False):
        logging.info("Opcion elegida: Busqueda de identidad.")
        search_identity(args.searchId)

    # Buscar clave publica
    elif (args.getPublicKey != False):
        logging.info("Opcion elegida: Busqueda de clave publica.")
        search_public_key(args.getPublicKey)

    # Borrar ID
    elif (args.deleteId != False):
        logging.info("Opcion elegida: Borrado de identidad.")
        delete_identity(args.deleteId)

    # Listado de ficheros
    elif (args.listF != False):
        logging.info("Opcion elegida: Listado de ficheros.")
        list_files()

    # Borrar ficheros
    elif (args.deleteF != False):
        logging.info("Opcion elegida: Borrado de ficheros.")
        delete_files(args.deleteF)

    # Subir archivo
    elif (args.upload != False):
        logging.info("Opcion elegida: Subida de archivos.")
        if(args.destId is False):
            logging.error("No se ha especificado una Identidad destino (--dest_id ID).")
            sys.exit(-1)
        upload_file(args.upload, args.destId)

    # Descargar archivo
    elif (args.download != False):
        logging.info("Opcion elegida: Descarga de archivos.")
        if(args.sourceId is False):
            logging.error("No se ha especificado una Identidad fuente (--source_id ID).")
            sys.exit(-1)
        download_file(args.download, args.sourceId)

    # Encriptar archivo
    elif (args.encrypt != False):
        logging.info("Opcion elegida: Encriptar archivos.")
        encrypt_file(args.encrypt)

    # Firmar archivo
    elif (args.sign != False):
        logging.info("Opcion elegida: Firmar archivos.")
        sign_file(args.sign)

    # Encriptar y firmar archivo
    elif (args.enc_sign != False):
        logging.info("Opcion elegida: Encriptar y firmar archivos.")
        enc_sign_file(args.enc_sign)

    # Error
    else:
        logging.error("No se ha especificado ninguna opcion.")
        parser.print_help()
        sys.exit(-1)
