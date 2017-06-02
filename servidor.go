package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/kabukky/httpscerts"
	. "github.com/mailjet/mailjet-apiv3-go"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var coleccion map[string]jsonUsuario
var codigos = make(map[string]string)

type jsonUsuario struct {
	Password []byte
	Salt     []byte
	Cuentas  map[string][]byte
	Token    string
	Codigo   string
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

func randomPassword(length int, charset string) string {
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
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
	//codigos := make(map[string]string)

	//Asignar handlers a rutas
	mux := http.NewServeMux()
	mux.Handle("/registrar", http.HandlerFunc(handlerRegistrar))
	mux.Handle("/login", http.HandlerFunc(handlerLogin))
	mux.Handle("/buscar", http.HandlerFunc(handlerBuscar))
	mux.Handle("/add", http.HandlerFunc(handlerAdd))
	mux.Handle("/modify", http.HandlerFunc(handlerModify))
	mux.Handle("/delete", http.HandlerFunc(handlerDelete))
	mux.Handle("/confirmarlogin", http.HandlerFunc(handlerConfirmarLogin))

	srv := &http.Server{Addr: ":10441", Handler: mux}
	fmt.Print("")
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

		newUser.Salt = makeSalt()
		newUser.Password = hashScrypt(newUser.Password, newUser.Salt, 64)
		newUser.Cuentas = make(map[string][]byte)
		coleccion[j.Usuario] = newUser

		// Since this is a binary format large parts of it will be unreadable
		encodeFile, _ = os.OpenFile("bd.gob", os.O_RDWR, 0666)
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
	encodeFile.Close()
	response(w, respuesta)
}

func handlerLogin(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonIdentificacion
	var respuesta jsonIdentificacionServidor
	respuesta.Valido = false
	decoder.Decode(&j)

	var encodeFile *os.File

	if _, err := os.Stat("bd.gob"); !os.IsNotExist(err) {
		encodeFile, err = os.OpenFile("bd.gob", os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}
		deserializer := gob.NewDecoder(encodeFile)
		deserializer.Decode(&coleccion)
		if _, ok := coleccion[j.Usuario]; ok {
			pass := hashScrypt([]byte(j.Password), coleccion[j.Usuario].Salt, 64)
			if bytes.Equal(coleccion[j.Usuario].Password, pass) {
				codigo := randomPassword(5, "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
				codigos[j.Usuario] = codigo
				myAPIkey := "59555f768951a44819acc29bd5fb340b"
				myPrivAPIkey := "bb1420a18893759e81e3a494a3fb79d2"
				mailjetClient := NewMailjetClient(myAPIkey, myPrivAPIkey)
				email := &InfoSendMail{
					FromEmail: "the_sapinyas@hotmail.com",
					FromName:  "Equipo sdsgestor",
					Subject:   "Código activación",
					TextPart:  codigo,
					Recipients: []Recipient{
						Recipient{
							Email: j.Usuario,
						},
					},
				}
				_, err := mailjetClient.SendMail(email)
				if err != nil {
					fmt.Println(err)
				}
				respuesta.Valido = true
			} else {
				respuesta.Valido = false
				respuesta.Mensaje = "Login incorrecto"
			}
		} else {
			respuesta.Valido = false
			respuesta.Mensaje = "Login incorrecto"
		}
	}
	response(w, respuesta)
	encodeFile.Close()
}

func handlerConfirmarLogin(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonCodigoIdentificacion
	var respuesta jsonIdentificacionServidor
	respuesta.Valido = false
	decoder.Decode(&j)
	if j.Codigo == codigos[j.Usuario] {
		delete(codigos, j.Usuario)
		respuesta.Valido = true
	} else {
		respuesta.Mensaje = "Código incorrecto"
	}

	response(w, respuesta)
}

func handlerBuscar(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonBuscar
	var respuesta jsonResultado
	respuesta.Encontrado = false
	decoder.Decode(&j)

	var encodeFile *os.File

	if _, err := os.Stat("bd.gob"); !os.IsNotExist(err) {
		encodeFile, err = os.OpenFile("bd.gob", os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}
		deserializer := gob.NewDecoder(encodeFile)
		deserializer.Decode(&coleccion)

		if _, ok := coleccion[j.Usuario].Cuentas[j.Cuenta]; ok {
			respuesta.Encontrado = true
			respuesta.Cuenta = j.Cuenta
			respuesta.Password = string(coleccion[j.Usuario].Cuentas[j.Cuenta])
		}
	}
	response(w, respuesta)
	encodeFile.Close()
}

func handlerAdd(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonNewPass
	var respuesta jsonIdentificacionServidor
	respuesta.Valido = false
	decoder.Decode(&j)

	var encodeFile *os.File

	if _, err := os.Stat("bd.gob"); !os.IsNotExist(err) {
		encodeFile, err = os.OpenFile("bd.gob", os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}
		deserializer := gob.NewDecoder(encodeFile)
		deserializer.Decode(&coleccion)

		if _, ok := coleccion[j.Usuario].Cuentas[j.Cuenta]; !ok {
			coleccion[j.Usuario].Cuentas[j.Cuenta] = []byte(j.Password)
			encodeFile, _ = os.OpenFile("bd.gob", os.O_RDWR, 0666)
			serializer := gob.NewEncoder(encodeFile)

			// Write to the file
			if err := serializer.Encode(coleccion); err != nil {
				respuesta.Valido = false
				respuesta.Mensaje = "Fallo en el servidor"

				panic(err)
			} else {
				respuesta.Valido = true
			}
		} else {
			respuesta.Valido = false
			respuesta.Mensaje = "Cuenta existente, para modificar la contraseña vaya a la sección modificar contraseña"
		}
	}
	response(w, respuesta)
	encodeFile.Close()
}

func handlerModify(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonNewPass
	var respuesta jsonIdentificacionServidor
	respuesta.Valido = false
	decoder.Decode(&j)

	var encodeFile *os.File

	if _, err := os.Stat("bd.gob"); !os.IsNotExist(err) {
		encodeFile, err = os.OpenFile("bd.gob", os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}
		deserializer := gob.NewDecoder(encodeFile)
		deserializer.Decode(&coleccion)

		if _, ok := coleccion[j.Usuario].Cuentas[j.Cuenta]; ok {
			coleccion[j.Usuario].Cuentas[j.Cuenta] = []byte(j.Password)
			encodeFile, _ = os.OpenFile("bd.gob", os.O_RDWR, 0666)
			serializer := gob.NewEncoder(encodeFile)

			// Write to the file
			if err := serializer.Encode(coleccion); err != nil {
				respuesta.Valido = false
				respuesta.Mensaje = "Fallo en el servidor"

				panic(err)
			} else {
				respuesta.Valido = true
			}
		} else {
			respuesta.Valido = false
			respuesta.Mensaje = "Cuenta no existente, para crear la cuenta y contraseña vaya a la sección añadir contraseña"
		}
	}
	response(w, respuesta)
	encodeFile.Close()
}

func handlerDelete(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	decoder := json.NewDecoder(req.Body)
	var j jsonNewPass
	var respuesta jsonIdentificacionServidor
	respuesta.Valido = false
	decoder.Decode(&j)

	var encodeFile *os.File

	if _, err := os.Stat("bd.gob"); !os.IsNotExist(err) {
		encodeFile, err = os.OpenFile("bd.gob", os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}
		deserializer := gob.NewDecoder(encodeFile)
		deserializer.Decode(&coleccion)

		if _, ok := coleccion[j.Usuario].Cuentas[j.Cuenta]; ok {
			delete(coleccion[j.Usuario].Cuentas, j.Cuenta)
			encodeFile, _ = os.OpenFile("bd.gob", os.O_RDWR, 0666)
			serializer := gob.NewEncoder(encodeFile)

			// Write to the file
			if err := serializer.Encode(coleccion); err != nil {
				respuesta.Valido = false
				respuesta.Mensaje = "Fallo en el servidor"

				panic(err)
			} else {
				respuesta.Valido = true
			}
		} else {
			respuesta.Valido = false
			respuesta.Mensaje = "Cuenta no existente"
		}
	}
	response(w, respuesta)
	encodeFile.Close()
}
