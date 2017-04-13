package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

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
	//var passAES string
	var passRegistro string
	var repitePassRegistro string
	var mensajeMenuPrincipal string
	var mensajeErrorLogin string
	var mensajeErrorRegistro string
	var mensajeAdministracion string
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
					//passAES = encode64(passLoginSHA3[32:64])
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
						limpiarPantallaWindows()
						opMenuUsuario = "0"
						for opMenuUsuario != "5" {
							if opMenuUsuario == "0" {
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
							}
							if opMenuUsuario != "5" {
								limpiarPantallaWindows()
								switch opMenuUsuario {
								case "1":
									fmt.Println("Buscar una cuenta")
									mensajeAdministracion = ""
								case "2":
									fmt.Println("Añadir una nueva cuenta")
									mensajeAdministracion = ""
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
							opMenuPrincipal = "2" // Mostramos el registro otra vez
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
