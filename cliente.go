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

func main() {
	var usuario string
	var password string
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	fmt.Println("Login:")
	reader := bufio.NewReader(os.Stdin)
	usuario, _ = reader.ReadString('\n')
	fmt.Println("Password:")
	password, _ = reader.ReadString('\n')
	//fmt.Printf("[LOG] Usuario: \"%s\", Password: \"%s\"\n", strings.TrimSpace(usuario), strings.TrimSpace(password))
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
