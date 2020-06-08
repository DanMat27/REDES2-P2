# practica2

Práctica 2

Para probar esta práctica no es necesario realizar ningún compilado previo, ya que se realiza
sobre Python3.

El usuario puede probar la funcionalidad de este cliente introduciendo los comandos que quiera
por teclado en la terminal de la siguiente manera: > python3 securebox_client.py --comando x

Concretamente, este cliente posee las siguientes funcionalidades (especificando el comando):

1. Mostrar la ayuda de los argumentos y opciones del cliente: > ... -h
2. Crear una identidad en el servidor: > ... --create_id "MI_NOMBRE" "EMAIL_UAM"
3. Borrar la identidad que se posea: > ... --delete_id MI_ID
4. Buscar la información de un usuario en concreto: > ... --search_id "XNOMBRE"
5. Conseguir la clave pública de un usuario: > ... --get_public_key "XID"
6. Subir un fichero encriptado y firmado al servidor a un destinatario: > ... --upload "FILE" --dest_id "XID"
7. Descargar un fichero encriptado y firmado del servidor para mi: > ... --download "FILE_ID" --source_id "XID"
8. Listar los archivos que te han mandado a ti en el servidor: > ... --list_files
9. Borrar un archivo que te han enviado del servidor: > ... --delete_file "FILE_ID"
10. Encriptar un archivo localmente para probar esta funcionalidad: > ... --encrypt "FILE"
11. Firmar un archivo localmente para probar esta funcionalidad: > ... --sign "FILE" 
12. Encriptar y firmar un archivo a la vez localmente: > ... --enc_sign "FILE"

(X indica un cualquiera existente o no)
(FILE_ID debe ser la ID que posee el archivo en el servidor)
(Los nombres es preferible que sean entre comillas dobles)

En el nombre del fichero debe especificarse solo el nombre y que se encuentre en la misma raiz
que el cliente.

Los archivos cifrados y descifrados se guardan localmente en las carpetas Cifrados/ y 
Descifrados/. La clave simétrica del usuario que posee este cliente se almacena localmente en
la carpeta Keys/.

El servidor utilizado para almacenar los ficheros y procesar las peticiones es el siguiente:
https://vega.ii.uam.es:8080

En el código se incluyen nuestros dos tokens de usuario (Daniel y Aitor) para las pruebas. 
Aunque este cliente está pensado para que lo utilice una sola persona con su propio token.
Concretamente, el token utilizado en la subida y descarga de archivos es token_mateo, por lo 
que esta variable global se debería de modificar si se quiere utilizar otro token propio aquí. 
En otras funciones de listados y búsquedas también se utiliza el token_aitor.

El usuario debe tener en cuenta que el destinatario de un archivo es el que puede borrarlo del
servidor o listar los que sean enviados a él. Estos tokens deben editarse a conciencia para 
esto.

Lo más recomendable es modificar ambos token con el mismo token propio, y así se evitan confusiones.
