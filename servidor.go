package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"httpscerts"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var coleccion map[string]jsonStruct

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	//login := req.Form.Get("Usuario")
	//pass := req.Form.Get("Password")

	decoder := json.NewDecoder(req.Body)
	var j jsonStruct
	decoder.Decode(&j)

	coleccion = make(map[string]jsonStruct)
	coleccion["login1"] = j

	// Create a file for IO
	encodeFile, err := os.Create("login.gob")
	if err != nil {
		panic(err)
	}

	// Since this is a binary format large parts of it will be unreadable
	encoder := gob.NewEncoder(encodeFile)

	// Write to the file
	if err := encoder.Encode(coleccion); err != nil {
		response(w, false, "Error")
		panic(err)
	}

	fmt.Println(coleccion["login1"].Usuario)
	response(w, true, "Texto enviado correctamente")
	encodeFile.Close()
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

type jsonStruct struct {
	Usuario  string
	Password string
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func main() {

	err := httpscerts.Check("cert.pem", "key.pem")
	// If they are not available, generate new ones.
	if err != nil {
		err = httpscerts.Generate("cert.pem", "key.pem", "127.0.0.1:10441")
		if err != nil {
			log.Fatal("Error: Couldn't create https certs.")
		}
	}

	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt)

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(handler))

	srv := &http.Server{Addr: ":10441", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan // espera señal SIGINT
	log.Println("Apagando servidor ...")

	// apagar servidor de forma segura
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Servidor detenido correctamente")
}
