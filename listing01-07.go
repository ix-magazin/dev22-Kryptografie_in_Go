/////////////////////////////////////
// Listing 1: Bytefeld chiffrieren //
/////////////////////////////////////

import (
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"
	"io"
)

func Encrypt(plain, key []byte) []byte {
	ciph := make([]byte, aes.BlockSize + len(plain))
	_, err := io.ReadFull(rand.Reader, ciph[:aes.BlockSize])

	block, err := aes.NewCipher(key)
	if err != nil {
			panic(err.Error())
	}

	stream := cipher.NewCTR(block, ciph[:aes.BlockSize])
	stream.XORKeyStream(ciph[aes.BlockSize:], plain)

	return ciph
}


////////////////////////////////////////////////////////
// Listing 2: Chiffrieren mit dem Galois Counter Mode //
////////////////////////////////////////////////////////

import ( 
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"
	"io"
)

func Encrypt(plain, key []byte) ([]byte, []byte) {
	block, _ := aes.NewCipher(key)

	aesgcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, aesgcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciph := aesgcm.Seal(nil, nonce, plain, nil)

	return nonce, ciph
}


/////////////////////////////////////////////////////////////
// Listing 3: Demoprogramm zur asymmetrischen Chiffrierung //
/////////////////////////////////////////////////////////////

package main

import (
    "crypto/cipher"
    "crypto/aes"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/rand"
    "bytes"
    "io"
)

const RsaLen = 1024    // RSA public key len in bits

func Encrypt(plain []byte, pubkey *rsa.PublicKey) []byte {
    key := make([]byte, 256/8)    // AES-256
    io.ReadFull(rand.Reader, key)

    encKey, _ := rsa.EncryptOAEP(sha256.New(), ↵rand.Reader, pubkey, key, nil)
    block, _ := aes.NewCipher(key)
    aesgcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, aesgcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ciph := aesgcm.Seal(nil, nonce, plain, nil)
    s := [][]byte{encKey, nonce, ciph}
    return bytes.Join(s, []byte{})
}

func Decrypt(ciph []byte, priv *rsa.PrivateKey) ([]byte, error) {
 encKey := ciph[:RsaLen/8]
   ciph = ciph[RsaLen/8:]
    key, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)

    block, _ := aes.NewCipher(key)
    aesgcm, _ := cipher.NewGCM(block)
    nonce := ciph[:aesgcm.NonceSize()]
    ciph = ciph[aesgcm.NonceSize():]

    return aesgcm.Open(nil, nonce, ciph, nil)
}

func main() {
    plain := make([]byte, 1000)

    priv, _ := rsa.GenerateKey(rand.Reader, RsaLen);
    pub := priv.PublicKey

    enc := Encrypt(plain, &pub)
    priv.Precompute()    // optional
    msg, _ := Decrypt(enc, priv)

    if !bytes.Equal(msg, plain) {
        panic("decryption failed!")
    }
}


///////////////////////////////////////////
// Listing 4: Privaten Schlüssel ablegen //
///////////////////////////////////////////

package main

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
)

const RsaLen = 2048    // RSA public key len in bits

func main() {
    pwd := []byte("my very personal password")

    priv, _ := rsa.GenerateKey(rand.Reader, RsaLen);

    // write encrypted private key to priv.pem
    der := x509.MarshalPKCS1PrivateKey(priv)
    block, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",der, pwd, x509.PEMCipherAES256)
    ioutil.WriteFile("priv.pem", pem.EncodeToMemory(block), 0644)

    // re-read and decrypt private key
    der, _ = ioutil.ReadFile("priv.pem")
    block, _ = pem.Decode(der)
    der, _ = x509.DecryptPEMBlock(block, pwd)
    priv, _ = x509.ParsePKCS1PrivateKey(der)
}


/////////////////////////////////////////////////
// Listing 5: Öffentlichen Schlüssel speichern //
/////////////////////////////////////////////////

package main

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "io/ioutil"
)

const RsaLen = 2048    // RSA public key len in bits

func main() {
    // write public key to pub.pem
    priv, _ := rsa.GenerateKey(rand.Reader, RsaLen);

    der := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
    block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}
    ioutil.WriteFile("pub.pem", pem.EncodeToMemory(block), 0644)

    // re-read public key
    der, _ = ioutil.ReadFile("pub.pem")
    block, _ = pem.Decode(der)
    der = block.Bytes
    pub, _ := x509.ParsePKCS1PublicKey(der)
}


//////////////////////////////////////////////////
// Listing 6: Zeitverzögerung mit Argon2 testen //
//////////////////////////////////////////////////

package main

import (
	"os"
	"io"
	"time"
	"fmt"
	"runtime"
	"crypto/rand"
	"sup_crypto/argon2"
)


func main() {
	pwd := []byte(os.Args[1])    // no error check!

	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	ram := 512*1024
	t0 := time.Now()
	key := argon2.IDKey(pwd, salt, 1, uint32(ram), uint8(runtime.NumCPU()<<1), 32)
	fmt.Printf("time: %v, key: %x\n", time.Since(t0), key)
}


///////////////////////////////////////////////////
// Listing 7: Zufallsgenerator Fortuna einsetzen //
///////////////////////////////////////////////////

package main

import (
    "io"
    "os"
    "github.com/seehuhn/fortuna"
)

const (
    Size = 1 << 30    // 1 GB
)

func main() {
    rng, _ := fortuna.NewRNG("")
    out, _ := os.Create("/dev/null")
    defer out.Close()

    io.CopyN(out, rng, Size)
}