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

const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + "¡!¿?$%&@*+-_"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomPassword(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

type jsonIdentificacion struct {
	Usuario  string
	Password string
}

type jsonIdentificacionServidor struct {
	Valido  bool
	Mensaje string
}

type jsonBuscar struct {
	Usuario string
	Cuenta  string
}

type jsonResultado struct {
	Encontrado bool
	Cuenta     string
	Password   string
}

type jsonNewPass struct {
	Usuario  string
	Cuenta   string
	Password string
}

func limpiarPantallaWindows() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func main() {
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
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
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
					//fmt.Printf("[DEBUG]	usuario	[%s]	password	[%s] \n", usuario, encode64(passSHA3))
					// Convertimos a JSON los datos que le enviaremos al servidor
					re := jsonIdentificacion{Usuario: usuario, Password: encode64(passSHA3)}
					jsonIdentificacion, err := json.Marshal(&re)
					chk(err)
					// Enviamos al servidor los datos de registro mediante POST
					r, err := client.Post("https://localhost:10441/login", "application/json", bytes.NewBuffer(jsonIdentificacion))
					chk(err)
					// Recogemos la respuesta del servidor y lo convertimos a JSON
					decoder := json.NewDecoder(r.Body)
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
										re := jsonBuscar{Usuario: usuario, Cuenta: nombreCuenta}
										jsonBuscar, err := json.Marshal(&re)
										chk(err)
										r, err := client.Post("https://localhost:10441/buscar", "application/json", bytes.NewBuffer(jsonBuscar))
										chk(err)
										// Recogemos la respuesta del servidor y lo convertimos a JSON
										decoder := json.NewDecoder(r.Body)
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
									re := jsonNewPass{Usuario: usuario, Cuenta: nombreCuenta, Password: encode64(encrypt([]byte(passCuenta), passAES))}
									jsonNewPass, err := json.Marshal(&re)
									chk(err)
									//encriptado := encrypt([]byte(passCuenta), passAES)
									//fmt.Printf("[DEBUG]	[ENCRYPT]	Usuario:	[%s]	Cuenta:	[%s]	Password:	[%s]\n", usuario, nombreCuenta, encode64(encrypt([]byte(passCuenta), passAES)))
									//fmt.Printf("[DEBUG]	[DECRYPT]	Usuario:	[%s]	Cuenta:	[%s]	Password:	[%s]\n", usuario, nombreCuenta, decrypt([]byte(encriptado), passAES))
									// Enviamos al servidor los datos de registro mediante POST
									r, err := client.Post("https://localhost:10441/add", "application/json", bytes.NewBuffer(jsonNewPass))
									chk(err)
									// Recogemos la respuesta del servidor y lo convertimos a JSON
									decoder := json.NewDecoder(r.Body)
									//var jis jsonIdentificacionServidor
									decoder.Decode(&jis)
									// Comprobamos la respuesta del servidor
									if jis.Valido == true {
										mensajeAdministracion = "[INFO] La cuenta se ha añadido correctamente!\n"
									} else {
										mensajeAdministracion = "[ERROR] " + jis.Mensaje + "\n"
									}
								case "3":
									fmt.Println("Modificar una cuenta")
									mensajeAdministracion = ""
								case "4":
									fmt.Println("Eliminar una cuenta")
									mensajeAdministracion = ""
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
						re := jsonIdentificacion{Usuario: usuario, Password: encode64(parteUnoPassRegistroSHA3)}
						jsonIdentificacion, err := json.Marshal(&re)
						chk(err)
						// Enviamos al servidor los datos de registro mediante POST
						r, err := client.Post("https://localhost:10441/registrar", "application/json", bytes.NewBuffer(jsonIdentificacion))
						chk(err)
						// Recogemos la respuesta del servidor y lo convertimos a JSON
						decoder := json.NewDecoder(r.Body)
						var jis jsonIdentificacionServidor
						decoder.Decode(&jis)
						// Comprobamos la respuesta del servidor
						if jis.Valido == true {
							mensajeMenuPrincipal = "[INFO] Registro de usuario realizado correctamente!\n"
						} else {
							mensajeErrorRegistro = "[ERROR] " + jis.Mensaje + "\n"
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
