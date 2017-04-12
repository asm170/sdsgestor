package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

func loginUsuario(usuario string, password string, validado bool) bool {
	return validado
}

func main() {
	var opMenuPrincipal string
	var opMenuUsuario string
	var usuario string
	var password string
	var passRegistro string
	var repitePassRegistro string
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
			fmt.Println("[1] Entrar")
			fmt.Println("[2] Registrate")
			fmt.Println("[3] Salir")
			fmt.Print("Elige una opcion: ")
			scanner.Scan()
			opMenuPrincipal = scanner.Text()
		}
		if opMenuPrincipal != "3" {
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
				password = scanner.Text()
				//fmt.Printf("[LOG] [Login] Usuario: [%s] Password: [%s]\n", usuario, password)
				// Comprobamos que el usuario es correcto
				if (len(usuario) > 0 && len(password) > 0) && loginUsuario(usuario, password, true) {
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
					mensajeErrorLogin = "[ERROR] El nombre de usuario y/o password son incorrectos\n"
				}
				/*
					TODO: Comprobamos que los datos de usuario
					son correctos, si son correctos, mostramos
					el menu del usuario. Si no son correctos
					volvemos a pedir al usuario los datos un
					determinado numero de veces
				*/
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
				// Comprobamos que el usuario ha introducido todos los datos
				if len(usuario) > 0 && len(passRegistro) > 0 && len(repitePassRegistro) > 0 {
					if passRegistro == repitePassRegistro {
						mensajeErrorRegistro = ""
						opMenuPrincipal = "0"
						// Resumimos en SHA3 el password
						//passRegistroSHA3 := sha512.Sum512([]byte(passRegistro))
						passRegistroSHA3 := hashSha512(passRegistro)
						// Partimos el resumen en dos partes iguales y la
						// primera parte se la enviamos al servidor
						parteUnoPassRegistroSHA3 := passRegistroSHA3[0:32]
						fmt.Printf("SHA3:           [%s]\n", passRegistroSHA3)
						fmt.Printf("SHA3[0  - 32]:  [%s]\n", encode64(parteUnoPassRegistroSHA3))
						//fmt.Printf("SHA3[32 - 64]:  [%s]\n", keyClient[32:64])
						re := jsonIdentificacion{Usuario: usuario, Password: encode64(parteUnoPassRegistroSHA3)}
						rJSON, err := json.Marshal(&re)
						chk(err)
						r, err := client.Post("https://localhost:10441", "application/json", bytes.NewBuffer(rJSON))
						chk(err)
						io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
						fmt.Println()
						//limpiarPantallaWindows()
					} else {
						mensajeErrorRegistro = "[ERROR] Los password no coinciden\n"
						opMenuPrincipal = "2" // Mostramos el registro otra vez
					}
				} else {
					mensajeErrorRegistro = "[ERROR] Te has dejado campos sin rellenar\n"
					opMenuPrincipal = "2" // Mostramos el registro otra vez
				}
				//mensajeErrorRegistro = "Los password no coinciden\n"
				//opMenuPrincipal = "2" // Mostramos el registro otra vez

				fmt.Printf("[LOG] [Registro] Usuario: [%s] Password: [%s] Repite password: [%s]\n", usuario, passRegistro, repitePassRegistro)
				/*
					TODO: Se comprueba que los datos proporcionados
					por el usuario son correctos, si no son correctos
					se mostraria al usuario los errores. Si son correctos
					se envian al servidor para añadir el nuevo usuario
					en el archivo JSON
				*/
			}

		}
	}

}
