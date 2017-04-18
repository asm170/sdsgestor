package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

//	Caracteres que formaran parte de la contraseña aleatoria
const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + "¡!¿?$%&@*+-_"

//	Struct que tendra los datos del usuario para la tarea de login
type jsonIdentificacion struct {
	Usuario  string
	Password string
}

//	Struct que tendra la respuesta del servidor
type jsonIdentificacionServidor struct {
	Valido  bool
	Mensaje string
}

//	Struct que se usara para realizar la busqueda de una cuenta
type jsonBuscar struct {
	Usuario string
	Cuenta  string
}

//	Struct que tendra la respuesta del servidor en la tarea de busqueda de una cuenta
type jsonResultado struct {
	Encontrado bool
	Cuenta     string
	Password   string
}

//	Struct que tendra los datos para añadir una nueva cuenta
type jsonNewPass struct {
	Usuario  string
	Cuenta   string
	Password string
}

/*
	Funcion que creara una cadena de caracteres de forma aleatoria
	Parametros entrada:
		length: int -> Longitud de la cadena
		charset: string -> Caracteres que formaran la cadena
*/
func randomPassword(length int, charset string) string {
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

//	Funcion que limpiara la consola utilizando el comando 'cls' de windows
func limpiarPantallaWindows() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

/*
	Funcion que enviara los datos al servidor
	Parametros entrada:
		ruta : string -> Ruta del servidor
		datos : interface{} -> Struct con los datos del cliente
	Devuelve:
		json.Decoder
*/
func send(ruta string, datos interface{}) *json.Decoder {
	//	Creamos un cliente especial que no comprueba la validez de los certificados
	//	esto es necesario por que usamos certificados autofirmados (para pruebas)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	datosJSON, err := json.Marshal(&datos)
	chk(err)
	// Enviamos al servidor los datos del cliente mediante POST
	r, err := client.Post("https://localhost:10441/"+ruta, "application/json", bytes.NewBuffer(datosJSON))
	chk(err)
	// Recogemos la respuesta del servidor y lo convertimos a JSON
	decoder := json.NewDecoder(r.Body)

	return decoder
}

/*
	Funcion que mostrara el menu de registro de usuario
	Parametros entrada:
		mensajeMenuRegistro : string -> Mensaje de INFO/ERROR del menu de registro
	Devuelve:
		opMenuPrincipal : string -> Opcion elegida del menu principal
		mensajeMenuPrincipal : string -> Mensaje de INFO/ERROR del menu principal
		mensajeMenuRegistro : string -> Mensaje de INFO/ERROR del menu de registro
*/
func menuRegistroUsuario(mensajeMenuRegistro string) (string, string, string) {
	// Variables para el registro de usuario
	var usuario string
	var passRegistro string
	var repitePassRegistro string
	// Mensajes de INFO/ERROR
	var mensajeMenuPrincipal string
	// Operacion del menu principal
	var opMenuPrincipal string
	// JSON que recibiremos del servidor
	var jis jsonIdentificacionServidor
	scanner := bufio.NewScanner(os.Stdin)
	// Limpiamos la terminal y mostramos el menu
	limpiarPantallaWindows()
	fmt.Println("+---------------------------------------------------+")
	fmt.Println("|  Introduce tus datos de usuario para registrarte  |")
	fmt.Println("+---------------------------------------------------+")
	fmt.Printf(mensajeMenuRegistro)
	// Solicitamos los datos al usuario
	fmt.Print("Nombre de usuario: ")
	scanner.Scan()
	usuario = scanner.Text()
	fmt.Print("Password: ")
	scanner.Scan()
	passRegistro = scanner.Text()
	fmt.Print("Repite el password: ")
	scanner.Scan()
	repitePassRegistro = scanner.Text()
	// Comprobamos que el usuario ha introducido correctamente los datos
	if len(usuario) > 0 && len(passRegistro) > 0 && len(repitePassRegistro) > 0 {
		if passRegistro == repitePassRegistro {
			// Resumimos en SHA3 el password
			passRegistroSHA3 := hashSha512(passRegistro)
			// Partimos el resumen en dos partes iguales y la
			// primera parte se la enviamos al servidor
			parteUnoPassRegistroSHA3 := passRegistroSHA3[0:32]
			// Convertimos a JSON los datos que le enviaremos al servidor
			datosJSON := jsonIdentificacion{Usuario: usuario, Password: encode64(parteUnoPassRegistroSHA3)}
			// Enviamos al servidor los datos
			decoder := send("registrar", datosJSON)
			decoder.Decode(&jis)
			// Comprobamos la respuesta del servidor
			if jis.Valido == true {
				mensajeMenuPrincipal = "[INFO] Registro de usuario realizado correctamente!\n"
				opMenuPrincipal = "0"
				mensajeMenuRegistro = ""
			} else {
				mensajeMenuRegistro = "[ERROR] " + jis.Mensaje + "\n"
				// Mostramos el registro otra vez
				opMenuPrincipal = "2"
			}
			limpiarPantallaWindows()
		} else {
			mensajeMenuRegistro = "[ERROR] Los password no coinciden\n"
			// Mostramos el registro otra vez
			opMenuPrincipal = "2"
		}
	} else {
		mensajeMenuRegistro = "[ERROR] Te has dejado campos sin rellenar\n"
		// Mostramos el registro otra vez
		opMenuPrincipal = "2"
	}

	return opMenuPrincipal, mensajeMenuPrincipal, mensajeMenuRegistro
}

/*
	Funcion que buscara la cuenta que introduce el usuario y si existe
	la mostrara por pantalla junto con el password descrifrado
	Parametros entrada:
		usuario : string -> Nombre del usuario que esta logueado
		passAES : []byte -> Clave AES para cifrar y descifrar
*/
func buscarCuenta(usuario string, passAES []byte) {
	// Mensajes de INFO/ERROR
	var mensajeBuscarCuenta string
	// Nombre de la cuenta a buscar
	var nombreCuenta = ""
	var opRepetirBusqueda = "1"
	// Struct que nos devolvera el servidor
	var jr jsonResultado
	scanner := bufio.NewScanner(os.Stdin)

	for opRepetirBusqueda != "2" {
		// Mostramos el menu del usuario
		for len(nombreCuenta) == 0 {
			limpiarPantallaWindows()
			fmt.Println("+---------------------+")
			fmt.Println("|  Buscar una cuenta  |")
			fmt.Println("+---------------------+")
			fmt.Printf(mensajeBuscarCuenta)
			fmt.Printf("Estas logueado como: [%s] \n", usuario)
			fmt.Print("Introduce el nombre de la cuenta que deseas buscar: ")
			scanner.Scan()
			nombreCuenta = scanner.Text()
			if len(nombreCuenta) == 0 {
				mensajeBuscarCuenta = "[ERROR] Introduce un nombre de cuenta para realizar la busqueda\n"
			} else {
				mensajeBuscarCuenta = ""
			}
		}
		// Enviamos al servidor los datos para realizar la busqueda de cuenta
		datosJSON := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
		// Enviamos al servidor los datos
		decoder := send("buscar", datosJSON)
		decoder.Decode(&jr)
		if jr.Encontrado == false {
			mensajeBuscarCuenta = "[INFO] No existe ninguna cuenta con ese nombre\n"
		}
		limpiarPantallaWindows()
		fmt.Println("+---------------------+")
		fmt.Println("|  Buscar una cuenta  |")
		fmt.Println("+---------------------+")
		fmt.Printf(mensajeBuscarCuenta)
		fmt.Printf("Estas logueado como: [%s] \n", usuario)
		// Mostramos la cuenta descifrada
		if jr.Encontrado == true {
			fmt.Printf("Cuenta:		[%s] \n", jr.Cuenta)
			fmt.Printf("Password:	[%s]\n", decrypt([]byte(decode64(jr.Password)), passAES))
		}
		// Le preguntamos al usuario si desea realizar otra busqueda
		fmt.Println("\nDeseas realizar otra busqueda? ")
		fmt.Println("[1] Si")
		fmt.Println("[2] No")
		fmt.Printf("Opcion: ")
		scanner.Scan()
		opRepetirBusqueda = scanner.Text()
		if opRepetirBusqueda != "1" && opRepetirBusqueda != "2" {
			opRepetirBusqueda = "1"
		} else {
			nombreCuenta = ""
			mensajeBuscarCuenta = ""
		}
	}
}

/*
	Funcion que añadira una nueva cuenta
	Parametros entrada:
		usuario : string -> Nombre del usuario que esta logueado
		passAES : []byte -> Clave AES para cifrar y descifrar
	Devuelve:
		mensajeAdministracion : string -> Mensaje de INFO/ERROR del menu de administracion
*/
func añadirCuenta(usuario string, passAES []byte) string {
	// Mensajes de INFO/ERROR
	var mensajeNuevaCuenta string
	var mensajeAdministracion string
	// Nombre de la cuenta que se quiere eliminar
	var nombreCuenta = ""
	// Flag que permitira al usuario obtener un password aleatorio
	var opAleatoria string
	var passCuenta string
	// Struct que nos devolvera el servidor
	var jr jsonResultado
	var jis jsonIdentificacionServidor
	scanner := bufio.NewScanner(os.Stdin)
	// Mostramos el menu del usuario
	for len(nombreCuenta) == 0 {
		limpiarPantallaWindows()
		fmt.Println("+---------------------------+")
		fmt.Println("|  Añadir una nueva cuenta  |")
		fmt.Println("+---------------------------+")
		fmt.Printf(mensajeNuevaCuenta)
		fmt.Printf("Estas logueado como: [%s] \n", usuario)
		fmt.Print("Introduce el nombre de la cuenta (Ejemplo: facebook): ")
		scanner.Scan()
		nombreCuenta = scanner.Text()
		if len(nombreCuenta) == 0 {
			mensajeNuevaCuenta = "[ERROR] Debes introducir un nombre para la nueva cuenta\n"
		} else {
			// Enviamos al servidor los datos para realizar la busqueda de cuenta
			datosJSON := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
			// Enviamos al servidor los datos
			decoder := send("buscar", datosJSON)
			decoder.Decode(&jr)
			if jr.Encontrado == true {
				mensajeNuevaCuenta = "[INFO] Ya existe una cuenta con este nombre\n"
				nombreCuenta = ""
			} else {
				mensajeNuevaCuenta = ""
			}
		}
	}
	for opAleatoria != "1" && opAleatoria != "2" {
		limpiarPantallaWindows()
		fmt.Println("+---------------------------+")
		fmt.Println("|  Añadir una nueva cuenta  |")
		fmt.Println("+---------------------------+")
		fmt.Printf(mensajeNuevaCuenta)
		fmt.Printf("Estas logueado como: [%s] \n", usuario)
		fmt.Println("Deseas generar aleatoriamente el password para la cuenta [" + nombreCuenta + "]? ")
		fmt.Println("[1] Si")
		fmt.Println("[2] No")
		fmt.Printf("Opcion: ")
		scanner.Scan()
		opAleatoria = scanner.Text()
	}
	// Password aleatorio
	if opAleatoria == "1" {
		// Generamos el password de forma aleatoriamente
		passCuenta = randomPassword(15, charset)
		//fmt.Printf("[DEBUG]	[random password]	passCuenta:	[%s]\n", passCuenta)
	} else { // Password manual
		passCuenta = ""
		repitePassCuenta := ""
		for len(passCuenta) == 0 || len(repitePassCuenta) == 0 || passCuenta != repitePassCuenta {
			limpiarPantallaWindows()
			fmt.Println("+---------------------------+")
			fmt.Println("|  Añadir una nueva cuenta  |")
			fmt.Println("+---------------------------+")
			fmt.Printf(mensajeNuevaCuenta)
			fmt.Printf("Estas logueado como: [%s] \n", usuario)
			fmt.Print("Password: ")
			scanner.Scan()
			passCuenta = scanner.Text()
			fmt.Print("Repite el password: ")
			scanner.Scan()
			repitePassCuenta = scanner.Text()
			if len(passCuenta) == 0 || len(repitePassCuenta) == 0 {
				mensajeNuevaCuenta = "[ERROR] Debes introducir un password\n"
			} else if passCuenta != repitePassCuenta {
				mensajeNuevaCuenta = "[ERROR] Los password deben coincidir\n"
			} else {
				mensajeNuevaCuenta = ""
			}
		}
	}
	// Ciframos con AES
	datosJSON := jsonNewPass{Usuario: usuario, Cuenta: nombreCuenta, Password: encode64(encrypt([]byte(passCuenta), passAES))}
	// Enviamos al servidor los datos
	decoder := send("add", datosJSON)
	decoder.Decode(&jis)
	// Comprobamos la respuesta del servidor
	if jis.Valido == true {
		mensajeAdministracion = "[INFO] La cuenta se ha añadido correctamente!\n"
	} else {
		mensajeAdministracion = "[INFO] " + jis.Mensaje + "\n"
	}

	return mensajeAdministracion
}

/*
	Funcion que modificara una cuenta
	Parametros entrada:
		usuario : string -> Nombre del usuario que esta logueado
		passAES : []byte -> Clave AES para cifrar y descifrar
	Devuelve:
		mensajeAdministracion : string -> Mensaje de INFO/ERROR del menu de administracion
*/
func modificarCuenta(usuario string, passAES []byte) string {
	// Mensajes de INFO/ERROR
	var mensajeModificarCuenta string
	var mensajeAdministracion string
	// Nombre de la cuenta que se quiere eliminar
	var nombreCuenta = ""
	// Flag que permitira al usuario obtener un password aleatorio
	var opAleatoria string
	var passCuenta string
	// Struct que nos devolvera el servidor
	var jr jsonResultado
	var jis jsonIdentificacionServidor
	scanner := bufio.NewScanner(os.Stdin)
	// Mostramos el menu del usuario
	for len(nombreCuenta) == 0 {
		limpiarPantallaWindows()
		fmt.Println("+------------------------+")
		fmt.Println("|  Modificar una cuenta  |")
		fmt.Println("+------------------------+")
		fmt.Printf(mensajeModificarCuenta)
		fmt.Printf("Estas logueado como: [%s] \n", usuario)
		fmt.Print("Introduce el nombre de la cuenta (Ejemplo: facebook): ")
		scanner.Scan()
		nombreCuenta = scanner.Text()
		if len(nombreCuenta) == 0 {
			mensajeModificarCuenta = "[ERROR] Debes introducir un nombre para la nueva cuenta\n"
		} else {
			// Enviamos al servidor los datos para realizar la busqueda de cuenta
			datosJSON := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
			// Enviamos al servidor los datos
			decoder := send("buscar", datosJSON)
			decoder.Decode(&jr)
			if jr.Encontrado == true {
				mensajeModificarCuenta = ""
			} else {
				mensajeModificarCuenta = "[INFO] No existe ninguna cuenta con ese nombre\n"
				nombreCuenta = ""
			}
		}
	}
	for opAleatoria != "1" && opAleatoria != "2" {
		limpiarPantallaWindows()
		fmt.Println("+------------------------+")
		fmt.Println("|  Modificar una cuenta  |")
		fmt.Println("+------------------------+")
		fmt.Printf(mensajeModificarCuenta)
		fmt.Printf("Estas logueado como: [%s] \n", usuario)
		fmt.Println("Deseas generar aleatoriamente el password para la cuenta [" + nombreCuenta + "]? ")
		fmt.Println("[1] Si")
		fmt.Println("[2] No")
		fmt.Printf("Opcion: ")
		scanner.Scan()
		opAleatoria = scanner.Text()
	}
	// Password aleatorio
	if opAleatoria == "1" {
		// Generamos el password de forma aleatoriamente
		passCuenta = randomPassword(15, charset)
		//fmt.Printf("[DEBUG]	[random password]	passCuenta:	[%s]\n", passCuenta)
	} else { // Password manual
		passCuenta = ""
		repitePassCuenta := ""
		for len(passCuenta) == 0 || len(repitePassCuenta) == 0 || passCuenta != repitePassCuenta {
			limpiarPantallaWindows()
			fmt.Println("+------------------------+")
			fmt.Println("|  Modificar una cuenta  |")
			fmt.Println("+------------------------+")
			fmt.Printf(mensajeModificarCuenta)
			fmt.Printf("Estas logueado como: [%s] \n", usuario)
			fmt.Print("Password: ")
			scanner.Scan()
			passCuenta = scanner.Text()
			fmt.Print("Repite el password: ")
			scanner.Scan()
			repitePassCuenta = scanner.Text()
			if len(passCuenta) == 0 || len(repitePassCuenta) == 0 {
				mensajeModificarCuenta = "[ERROR] Debes introducir un password\n"
			} else if passCuenta != repitePassCuenta {
				mensajeModificarCuenta = "[ERROR] Los password deben coincidir\n"
			} else {
				mensajeModificarCuenta = ""
			}
		}
	}
	// Ciframos con AES
	datosJSON := jsonNewPass{Usuario: usuario, Cuenta: nombreCuenta, Password: encode64(encrypt([]byte(passCuenta), passAES))}
	// Enviamos al servidor los datos
	decoder := send("modify", datosJSON)
	decoder.Decode(&jis)
	// Comprobamos la respuesta del servidor
	if jis.Valido == true {
		mensajeAdministracion = "[INFO] La cuenta se ha modificado correctamente!\n"
	} else {
		mensajeAdministracion = "[INFO] " + jis.Mensaje + "\n"
	}

	return mensajeAdministracion
}

/*
	Funcion que eliminara una cuenta
	Parametros entrada:
		usuario : string -> Nombre del usuario que esta logueado
	Devuelve
		mensajeAdministracion : string -> Mensaje de INFO/ERROR del menu de administracion
*/
func eliminarCuenta(usuario string) string {
	// Mensajes de INFO/ERROR
	var mensajeEliminarCuenta string
	var mensajeAdministracion string
	// Nombre de la cuenta que se quiere eliminar
	var nombreCuenta = ""
	// Flag de confirmacion para eliminar la cuenta
	var opEliminar string
	// Struct de datos que nos devolvera el servidor
	var jis jsonIdentificacionServidor
	var jr jsonResultado
	scanner := bufio.NewScanner(os.Stdin)
	// Mostramos el menu del usuario
	for len(nombreCuenta) == 0 {
		limpiarPantallaWindows()
		fmt.Println("+-----------------------+")
		fmt.Println("|  Eliminar una cuenta  |")
		fmt.Println("+-----------------------+")
		fmt.Printf(mensajeEliminarCuenta)
		fmt.Printf("Estas logueado como: [%s] \n", usuario)
		fmt.Print("Introduce el nombre de la cuenta que deseas eliminar: ")
		scanner.Scan()
		nombreCuenta = scanner.Text()
		if len(nombreCuenta) == 0 {
			mensajeEliminarCuenta = "[ERROR] Introduce un nombre de cuenta para eliminarla\n"
		} else {
			// Enviamos al servidor los datos para realizar la busqueda de cuenta
			datosJSON := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
			// Enviamos al servidor los datos
			decoder := send("buscar", datosJSON)
			decoder.Decode(&jr)
			if jr.Encontrado == false {
				mensajeEliminarCuenta = "[INFO] La cuenta que se quiere eliminar no existe\n"
				nombreCuenta = ""
			} else {
				mensajeEliminarCuenta = ""
				fmt.Println("Estas seguro de querer eliminar la cuenta [" + nombreCuenta + "]? ")
				fmt.Println("[1] Si")
				fmt.Println("[2] No")
				fmt.Printf("Opcion: ")
				scanner.Scan()
				opEliminar = scanner.Text()
				if opEliminar == "1" {
					// Enviamos al servidor los datos para realizar el borrado de la cuenta
					datosJSON := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
					// Enviamos al servidor los datos
					decoder := send("delete", datosJSON)
					decoder.Decode(&jis)
					if jis.Valido == true {
						mensajeAdministracion = "[INFO] La cuenta se ha eliminado correctamente!\n"
					} else {
						mensajeAdministracion = "[INFO] " + jis.Mensaje + "\n"
					}
				}
			}
		}
	}
	return mensajeAdministracion
}

/*
	Funcion que mostrara el menu de administracion del usuario
	Parametros entrada:
		usuario : string -> Nombre del usuario que esta logueado
		passAES : []byte -> Clave AES para cifrar y descifrar
	Devuelve:
		opMenuPrincipal : string -> Operacion elegida en el menu principal
*/
func menuUsuario(usuario string, passAES []byte) string {
	var opMenuUsuario = "0"
	var opMenuPrincipal string
	// Mensajes de INFO/ERROR
	var mensajeAdministracion string
	scanner := bufio.NewScanner(os.Stdin)
	for opMenuUsuario != "5" {
		if opMenuUsuario == "0" {
			limpiarPantallaWindows()
			// Mostramos el menu del usuario
			fmt.Println("+---------------------------+")
			fmt.Println("|  Panel de administracion  |")
			fmt.Println("+---------------------------+")
			fmt.Printf(mensajeAdministracion)
			fmt.Printf("Estas logueado como: [%s] \n", usuario)
			fmt.Println("[1] Buscar una cuenta")
			fmt.Println("[2] Añadir una nueva cuenta")
			fmt.Println("[3] Modificar una cuenta")
			fmt.Println("[4] Eliminar una cuenta")
			fmt.Println("[5] Salir")
			fmt.Print("Elige una opcion: ")
			scanner.Scan()
			opMenuUsuario = scanner.Text()
			mensajeAdministracion = ""
			if len(opMenuUsuario) != 1 {
				opMenuUsuario = "0"
			}
		}
		if opMenuUsuario != "5" {
			limpiarPantallaWindows()
			switch opMenuUsuario {
			case "1": //	BUSCAR CUENTA
				buscarCuenta(usuario, passAES)
			case "2": //	AÑADIR CUENTA
				mensajeAdministracion = añadirCuenta(usuario, passAES)
			case "3": //	MODIFICAR CUENTA
				mensajeAdministracion = modificarCuenta(usuario, passAES)
			case "4": //	ELIMINAR CUENTA
				mensajeAdministracion = eliminarCuenta(usuario)
			}
			// Colocamos el flag a 0 para que vuelva a mostrar el menu del usuario
			opMenuUsuario = "0"
		}
	}
	// Colocamos el flag a 0 para volver a mostrar el menu principal
	opMenuPrincipal = "0"

	return opMenuPrincipal
}

/*
	Funcion que mostrara el menu para que el usuario se pueda loguear
	Parametros entrada:
		mensajeLogin : string -> Mensaje de INFO/ERROR del menu de login
	Devuelve:
		opMenuPrincipal : string -> Opcion elegida del menu principal
		mensajeLogin : string -> Mensaje de INFO/ERROR del menu de login
*/
func menuLoginUsuario(mensajeLogin string) (string, string) {
	// Variables para el login de usuario
	var usuario string
	var passLogin string
	// Operacion del menu principal
	var opMenuPrincipal string
	// Clave para cifrar y descrifrar AES en el cliente
	var passAES []byte
	// JSON que recibiremos del servidor
	var jis jsonIdentificacionServidor
	scanner := bufio.NewScanner(os.Stdin)
	// Limpiamos la terminal y mostramos el menu
	limpiarPantallaWindows()
	fmt.Println("+----------------------------------------------+")
	fmt.Println("|  Introduce tus datos de usuario para entrar  |")
	fmt.Println("+----------------------------------------------+")
	fmt.Printf(mensajeLogin)
	fmt.Print("Nombre de usuario: ")
	scanner.Scan()
	usuario = scanner.Text()
	fmt.Print("Password: ")
	scanner.Scan()
	passLogin = scanner.Text()
	// Comprobamos que el usuario ha introducido los datos correctamente
	if len(usuario) > 0 && len(passLogin) > 0 {
		// Resumimos el password con SHA3
		passLoginSHA3 := hashSha512(passLogin)
		// Partimos el SHA3 generado
		passSHA3 := passLoginSHA3[0:32]
		passAES = passLoginSHA3[32:64]
		// Convertimos a JSON los datos que le enviaremos al servidor
		datosJSON := jsonIdentificacion{Usuario: usuario, Password: encode64(passSHA3)}
		// Enviamos al servidor los datos
		decoder := send("login", datosJSON)
		decoder.Decode(&jis)
		// Comprobamos que el usuario y password son correctos
		if jis.Valido == true {
			mensajeLogin = ""
			// Mostramos el menu de usuario
			opMenuPrincipal = menuUsuario(usuario, passAES)
		} else {
			mensajeLogin = "[ERROR] " + jis.Mensaje + "\n"
			// Mostramos el login otra vez
			opMenuPrincipal = "1"
		}
	} else {
		mensajeLogin = "[ERROR] El nombre de usuario y/o password no pueden quedar vacios\n"
		// Mostramos el login otra vez
		opMenuPrincipal = "1"
	}

	return opMenuPrincipal, mensajeLogin
}

// Funcion principal
func main() {
	// Opcion elegida del menu principal
	var opMenuPrincipal = "0"
	// Mensajes de INFO/ERROR en los menus
	var mensajeMenuPrincipal string
	var mensajeLogin string
	var mensajeMenuRegistro string
	scanner := bufio.NewScanner(os.Stdin)
	//	Se mostrara el menu hasta que el usuario elija la opcion 'Salir'
	for opMenuPrincipal != "3" {
		limpiarPantallaWindows()
		if opMenuPrincipal == "0" {
			fmt.Println("+-----------------------------------------+")
			fmt.Println("|  Bienvenido a tu Gestor de Contraseñas! |")
			fmt.Println("+-----------------------------------------+")
			fmt.Printf(mensajeMenuPrincipal)
			fmt.Println("[1] Entrar")
			fmt.Println("[2] Registrate")
			fmt.Println("[3] Salir")
			fmt.Print("Elige una opcion: ")
			scanner.Scan()
			opMenuPrincipal = scanner.Text()
			if len(opMenuPrincipal) != 1 {
				opMenuPrincipal = "0"
			}
		}
		if opMenuPrincipal != "3" {
			mensajeMenuPrincipal = ""
			switch opMenuPrincipal {
			case "1": //	LOGIN DE USUARIO
				opMenuPrincipal, mensajeLogin = menuLoginUsuario(mensajeLogin)
				//fmt.Printf("[DEBUG]	opMenuPrincipal:	[%s]	mensajeMenuRegistro:	[%s]\n", opMenuPrincipal, mensajeMenuRegistro)
			case "2": //	REGISTRO DE USUARIO
				opMenuPrincipal, mensajeMenuPrincipal, mensajeMenuRegistro = menuRegistroUsuario(mensajeMenuRegistro)
				//fmt.Printf("[DEBUG]	opMenuPrincipal:	[%s]	mensajeMenuPrincipal:	[%s]	mensajeMenuRegistro:	[%s]\n", opMenuPrincipal, mensajeMenuPrincipal, mensajeMenuRegistro)
			}
		}
	}
}
