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
	Parametros:
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
	Parametros:
	ruta : string -> Ruta del servidor
	datos : interface{} -> Struct con los datos del cliente
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

func menuRegistroUsuario(mensajeMenuRegistro string) (string, string, string) {
	// Variables para el registro de usuario
	var usuario string
	var passRegistro string
	var repitePassRegistro string
	// Mensajes de INFO/ERROR
	//var mensajeMenuRegistro string
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

// Funcion principal
func main() {
	// Opcion elegida del menu principal
	var opMenuPrincipal = "0"
	// Mensajes de INFO/ERROR en los menus
	var mensajeMenuPrincipal string
	var mensajeMenuRegistro string

	scanner := bufio.NewScanner(os.Stdin)

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
		//	Se mostrara el menu hasta que el usuario elija la opcion 'Salir'
		if opMenuPrincipal != "3" {
			mensajeMenuPrincipal = ""
			switch opMenuPrincipal {
			case "1": //	LOGIN DE USUARIO
				// Activamos el flag para que vuelva al menu principal
				opMenuPrincipal = "0"
			case "2": //	REGISTRO DE USUARIO
				opMenuPrincipal, mensajeMenuPrincipal, mensajeMenuRegistro = menuRegistroUsuario(mensajeMenuRegistro)
				//fmt.Printf("[DEBUG]	opMenuPrincipal:	[%s]	mensajeMenuPrincipal:	[%s]	mensajeMenuRegistro:	[%s]\n", opMenuPrincipal, mensajeMenuPrincipal, mensajeMenuRegistro)
			}
		}
	}
}

// Funcion principal
func mainOld() {
	var opMenuPrincipal string
	var opMenuUsuario string
	var usuario string
	var passLogin string
	var passAES []byte
	var passRegistro string
	var passCuenta string
	var repitePassRegistro string
	var mensajeMenuPrincipal string
	var mensajeErrorLogin string
	var mensajeErrorRegistro string
	var mensajeAdministracion string
	var mensajeNuevaCuenta string
	var mensajeBuscarCuenta string
	var mensajeEliminarCuenta string

	limpiarPantallaWindows()
	opMenuPrincipal = "0"
	scanner := bufio.NewScanner(os.Stdin)
	for opMenuPrincipal != "3" {
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
		}
		if opMenuPrincipal != "3" {
			mensajeMenuPrincipal = ""
			switch opMenuPrincipal {
			case "1": // Login de usuario
				limpiarPantallaWindows()
				fmt.Println("+----------------------------------------------+")
				fmt.Println("|  Introduce tus datos de usuario para entrar  |")
				fmt.Println("+----------------------------------------------+")
				fmt.Printf(mensajeErrorLogin)
				fmt.Print("Nombre de usuario: ")
				scanner.Scan()
				usuario = scanner.Text()
				fmt.Print("Password: ")
				scanner.Scan()
				passLogin = scanner.Text()
				// Comprobamos que el usuario es correcto
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
					var jis jsonIdentificacionServidor
					decoder.Decode(&jis)
					/*
						Comprobamos que los datos de usuario
						son correctos, si son correctos, mostramos
						el menu del usuario. Si no son correctos
						volvemos a pedir al usuario los datos
					*/
					if jis.Valido == true {
						mensajeErrorLogin = ""
						opMenuUsuario = "0"
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
							}
							if opMenuUsuario != "5" {
								limpiarPantallaWindows()
								switch opMenuUsuario {
								case "1":
									nombreCuenta := ""
									var opRepetirBusqueda string
									opRepetirBusqueda = "1"
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
										var jr jsonResultado
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
										scanner.Scan()
										opRepetirBusqueda = scanner.Text()
										nombreCuenta = ""
										mensajeBuscarCuenta = ""
									}
								case "2":
									nombreCuenta := ""
									var opAleatoria string
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
											mensajeNuevaCuenta = ""
										}
									}
									for opAleatoria != "1" && opAleatoria != "2" {
										limpiarPantallaWindows()
										fmt.Println("+---------------------------+")
										fmt.Println("|  Añadir una nueva cuenta  |")
										fmt.Println("+---------------------------+")
										fmt.Printf(mensajeNuevaCuenta)
										fmt.Printf("Estas logueado como: [%s] \n", usuario)
										fmt.Println("Deseas generar aleatoriamente el password? ")
										fmt.Println("[1] Si")
										fmt.Println("[2] No")
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
								case "3":
									fmt.Println("Modificar una cuenta")
									mensajeAdministracion = ""
								case "4":
									var opEliminar string
									nombreCuenta := ""
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
											mensajeEliminarCuenta = ""
										}
									}
									fmt.Println("Estas seguro de querer eliminar la cuenta [" + nombreCuenta + "]? ")
									fmt.Println("[1] Si")
									fmt.Println("[2] No")
									scanner.Scan()
									opEliminar = scanner.Text()
									if opEliminar == "1" {
										// Enviamos al servidor los datos para realizar el borrado de la cuenta
										datosJSON := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
										// Enviamos al servidor los datos
										decoder := send("delete", datosJSON)
										//var jis jsonIdentificacionServidor
										decoder.Decode(&jis)
										if jis.Valido == true {
											mensajeAdministracion = "[INFO] La cuenta se ha eliminado correctamente!\n"
										} else {
											mensajeAdministracion = "[INFO] " + jis.Mensaje + "\n"
										}
									}
								}
								// Colocamos el flag a 0 para que vuelva a mostrar el menu del usuario
								opMenuUsuario = "0"
							}
						}
						// Colocamos el flag a 0 para que vuelva a mostrar el menu principal
						opMenuPrincipal = "0"
						limpiarPantallaWindows()
					} else {
						mensajeErrorLogin = "[ERROR] " + jis.Mensaje + "\n"
					}
				}
			case "2": // Registro de usuario
				limpiarPantallaWindows()
				fmt.Println("+---------------------------------------------------+")
				fmt.Println("|  Introduce tus datos de usuario para registrarte  |")
				fmt.Println("+---------------------------------------------------+")
				fmt.Printf(mensajeErrorRegistro)
				fmt.Print("Nombre de usuario: ")
				scanner.Scan()
				usuario = scanner.Text()
				fmt.Print("Password: ")
				scanner.Scan()
				passRegistro = scanner.Text()
				fmt.Print("Repite el password: ")
				scanner.Scan()
				repitePassRegistro = scanner.Text()
				/*
					Se comprueba que los datos proporcionados
					por el usuario son correctos, si no son correctos
					se mostraria al usuario los errores. Si son correctos
					se envian al servidor para añadir el nuevo usuario
					en el archivo JSON
				*/
				if len(usuario) > 0 && len(passRegistro) > 0 && len(repitePassRegistro) > 0 {
					if passRegistro == repitePassRegistro {
						mensajeErrorRegistro = ""
						opMenuPrincipal = "0"
						// Resumimos en SHA3 el password
						passRegistroSHA3 := hashSha512(passRegistro)
						// Partimos el resumen en dos partes iguales y la
						// primera parte se la enviamos al servidor
						parteUnoPassRegistroSHA3 := passRegistroSHA3[0:32]
						// Convertimos a JSON los datos que le enviaremos al servidor
						datosJSON := jsonIdentificacion{Usuario: usuario, Password: encode64(parteUnoPassRegistroSHA3)}
						// Enviamos al servidor los datos
						decoder := send("registrar", datosJSON)
						var jis jsonIdentificacionServidor
						decoder.Decode(&jis)
						// Comprobamos la respuesta del servidor
						if jis.Valido == true {
							mensajeMenuPrincipal = "[INFO] Registro de usuario realizado correctamente!\n"
						} else {
							mensajeErrorRegistro = "[INFO] " + jis.Mensaje + "\n"
							//opMenuPrincipal = "2" // Mostramos el registro otra vez
						}
						limpiarPantallaWindows()
					} else {
						mensajeErrorRegistro = "[ERROR] Los password no coinciden\n"
						opMenuPrincipal = "2" // Mostramos el registro otra vez
					}
				} else {
					mensajeErrorRegistro = "[ERROR] Te has dejado campos sin rellenar\n"
					opMenuPrincipal = "2" // Mostramos el registro otra vez
				}
			}
		}
	}
}
