# sdsgestor
Gestor de contraseñas

29/03 (Esquema en papel)
Arquitectura Cliente/Servidor
Comunicacion
JSON (uso de JSON para el transporte de datos, Marshal, UnMarshal)
Estructuras de datos
Login (no hace falta estar implementado, explicar como lo haremos)
   El cliente resume la contraseña con una hash y lo envia al servidor.
   El servidor vuelve a resumir la hash con una SALT y compara la hash con la de la BDD.
