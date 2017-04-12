package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"golang.org/x/crypto/scrypt"
	"io"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data string, key []byte) (out string) {
	byteData := decode64(data)
	preout := make([]byte, len(byteData)+16)
	rand.Read(preout[:16])
	blk, err := aes.NewCipher(key)
	chk(err)
	ctr := cipher.NewCTR(blk, preout[:16])
	ctr.XORKeyStream(preout[16:], byteData)
	out = encode64(preout)
	return
}

// función para descifrar (con AES en este caso)
func decrypt(data string, key []byte) (out string) {
	byteData := decode64(data)
	preout := make([]byte, len(byteData)-16)
	blk, err := aes.NewCipher(key)
	chk(err)
	ctr := cipher.NewCTR(blk, byteData[:16])
	ctr.XORKeyStream(preout, byteData[16:])
	out = encode64(preout)
	return
}

// función para hashear con scrypt
func hashScrypt(data string, salt []byte, bytes int) (out []byte) {
	out, _ = scrypt.Key([]byte(data), salt, 16384, 8, 1, bytes)
	return
}

// función para hashear con sha3 512
func hashSha512(data string) (out [64]byte) {
	out = sha512.Sum512([]byte(data))
	return
}

func makeSalt() (out []byte) {
	out = make([]byte, 32)
	io.ReadFull(rand.Reader, out)
	return
}
