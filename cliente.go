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

type jsonStruct struct {
	Usuario  string
	Password string
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
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
	var repitePassword string
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
					mensajeErrorLogin = "El nombre de usuario y/o password son incorrectos\n"
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
				password = scanner.Text()
				fmt.Print("Repite el password: ")
				scanner.Scan()
				repitePassword = scanner.Text()
				//mensajeErrorRegistro = "Los password no coinciden\n"
				//opMenuPrincipal = "2" // Mostramos el registro otra vez
				opMenuPrincipal = "0"
				limpiarPantallaWindows()

				fmt.Printf("[LOG] [Registro] Usuario: [%s] Password: [%s] Repite password: [%s]\n", usuario, password, repitePassword)
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
	// Parseamos a JSON los datos del usuario
	re := jsonStruct{Usuario: usuario, Password: password}
	rJSON, err := json.Marshal(&re)
	chk(err)
	r, err := client.Post("https://localhost:10441", "application/json", bytes.NewBuffer(rJSON))
	/*
			// ** ejemplo de registro
			data := url.Values{}             // estructura para contener los valores
			data.Set("cmd", "hola")          // comando (string)
			data.Set("mensaje", "miusuario") // usuario (string)
		r, err := client.PostForm("https://localhost:10441", data) // enviamos por POST
	*/
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()
}
