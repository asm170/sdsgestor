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
##### Primer paso
ruta /login
#### Cliente 
guarda la segunda parte de la clave como clave para aes
Envía jsonIdentificacion{Usuario:string, Password:string} (Password = password de autentificación)
#### Servidor
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string, Token:string} 
y envía correo con código de identificación
##### Segundo paso
ruta /loginCodigo
#### Cliente
recibe si ususario y contraseña son correctos y muestra para introducir clave
envía código de identificación
envía jsonCodigoIdentificacion{Codigo:string}
#### Servidor
borra código
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string, Token:string} 

### Buscar contraseñas
ruta /buscar
#### Cliente
Envía jsonBuscar{Usuario:string, Cuenta:string, Token:string}
#### Servidor
Devuelve jsonResultado{Encontrado:bool, Cuenta:string, Password:string, Mensaje:string} (Password cifrada con aes)

### Añadir contraseñas
ruta /add
#### Cliente
cifra contraseña con aes
Envía jsonNewPass{Usuario:string, Cuenta:string, Password:string, Token:string}
#### Servidor
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string}(reutilizamos por si hay algún error del servidor)

### Modificar contraseñas
ruta /modify
#### Cliente
Envía jsonNewPass{Usuario:string, Cuenta:string, Password:string, Token:string}
#### Servidor
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string}(reutilizamos por si hay algún error del servidor)

### Eliminar contraseñas
ruta /delete
#### Cliente
Envía jsonBuscar{Usuario:string, Cuenta:, Token:string}
devuelve jsonIdentificacionServidor{Valido:bool, Mensaje:string}(reutilizamos por si hay algún error del servidor)



memoria:
	-Pequeña descripción de la aplicación
	-Descripción de la seguridad utilizada
		-Explicar funcionalidades 1 a 1
			-Parte cliente detallada
			-Parte servidor detallada