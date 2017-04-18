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

var coleccion map[string]jsonUsuario

type jsonUsuario struct {
	Password []byte
	Salt     []byte
	Cuentas  map[string][]byte
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

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

/*type jsonStruct struct {
	Usuario  string
	Password string
}*/

// función para escribir una respuesta del servidor
func response(w io.Writer, r interface{}) {
	rJSON, err := json.Marshal(&r)
	chk(err)
	w.Write(rJSON)
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

	//Asignar handlers a rutas
	mux := http.NewServeMux()
	mux.Handle("/registrar", http.HandlerFunc(handlerRegistrar))

	srv := &http.Server{Addr: ":10441", Handler: mux}
	log.Println("Servidor en marcha")
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

func handlerRegistrar(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonIdentificacion
	var respuesta jsonIdentificacionServidor
	respuesta.Valido = true
	decoder.Decode(&j)
	var newUser jsonUsuario
	newUser.Password = []byte(j.Password)
	coleccion = make(map[string]jsonUsuario)

	var encodeFile *os.File

	if _, err := os.Stat("bd.gob"); os.IsNotExist(err) {
		// Create a file for IO
		encodeFile, err = os.Create("bd.gob")
		if err != nil {
			panic(err)
		}
	} else {
		encodeFile, err = os.OpenFile("bd.gob", os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}
		deserializer := gob.NewDecoder(encodeFile)
		deserializer.Decode(&coleccion)
	}

	if _, ok := coleccion[j.Usuario]; !ok {
		coleccion[j.Usuario] = newUser

		// Since this is a binary format large parts of it will be unreadable
		serializer := gob.NewEncoder(encodeFile)

		// Write to the file
		if err := serializer.Encode(coleccion); err != nil {
			respuesta.Valido = false
			respuesta.Mensaje = "Fallo en el servidor"
			response(w, respuesta)
			panic(err)
		}
	} else {
		respuesta.Valido = false
		respuesta.Mensaje = "Nombre ya en uso, por favor escoja otro"
	}

	fmt.Println(respuesta.Mensaje)
	response(w, respuesta)
	encodeFile.Close()
}
