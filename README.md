# sdsgestor
Gestor de contraseñas

### Cuando te registras
ruta /registrar
#### Cliente
Envía jsonIdentificacion{Usuario:string, Password:string} (Password = password de autentificación)
#### Servidor
Serializa todo en un fichero
devuelve booleano jsonIdentificacionServidor{Valido:bool, Mensaje:string} 

### Cuando logueas
ruta /login
#### Cliente 
guarda la segunda parte de la clave como clave para aes
Envía jsonIdentificacion{Usuario:string, Password:string} (Password = password de autentificación)
#### Servidor
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string} 

### Buscar contraseñas
ruta /buscar
#### Cliente
Envía jsonBuscar{Usuario:string, Cuenta:string}
#### Servidor
Devuelve jsonResultado{Encontrado:bool, Cuenta:string, Password:string} (Password cifrada con aes)

### Añadir contraseñas
ruta /add
#### Cliente
cifra contraseña con aes
Envía jsonNewPass{Usuario:string, Cuenta:string, Password:string}
#### Servidor
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string}(reutilizamos por si hay algún error del servidor)

### Modificar contraseñas
ruta /modify
#### Cliente
Envía jsonNewPass{Usuario:string, Cuenta:string, Password:string}
#### Servidor
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string}(reutilizamos por si hay algún error del servidor)

### Eliminar contraseñas
ruta /delete
#### Cliente
Envía jsonBuscar{Usuario:string, Cuenta:string}
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string}(reutilizamos por si hay algún error del servidor)