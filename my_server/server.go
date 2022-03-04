package main

import (
	"encoding/base64"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const (
	serverAddr             = "0.0.0.0:8080"
	defaultSealPath        = "/data/.sgx_seel/my_priv_key.seal"
	attestationProviderURL = "https://shareduks.uks.attest.azure.net"
)

var myPrivKey = []byte("my_priv_key")

func getProductSealKey() []byte {
	key, _, err := enclave.GetProductSealKey()
	if err != nil {
		panic(err)
	}

	return key
}

func generateAndSealPrivKey() {
	if _, err := os.Stat(defaultSealPath); os.IsNotExist(err) {
		fmt.Println("Create privKey and seal.")

		err := os.MkdirAll(filepath.Dir(defaultSealPath), 0755)
		if err != nil {
			panic(err)
		}

		privKey, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			panic(err)
		}

		encPriv, err := ecrypto.Encrypt(privKey.Serialize(), getProductSealKey(), myPrivKey)
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(defaultSealPath, encPriv, 0755)
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Already exist seal.")
	}
}

func getPrivkeyFromSeal() []byte {
	file, err := ioutil.ReadFile(defaultSealPath)
	if err != nil {
		panic(fmt.Errorf("you have to run 'create-key' first. %e", err))
	}

	privKeyBytes, err := ecrypto.Decrypt(file, getProductSealKey(), myPrivKey)
	if err != nil {
		panic(err)
	}

	return privKeyBytes
}

func getPubkey() []byte {
	privKeyBytes := getPrivkeyFromSeal()

	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	fmt.Println(base64.StdEncoding.EncodeToString(pubKey.SerializeCompressed()))

	return pubKey.SerializeCompressed()
}

func main() {
	generateAndSealPrivKey()

	pubkey := getPubkey()

	// Cerate an Azure Attestation Token.
	token, err := enclave.CreateAzureAttestationToken(pubkey, attestationProviderURL)
	if err != nil {
		panic(err)
	}
	fmt.Println("🆗 Created an Microsoft Azure Attestation Token.")

	// Create HTTPS server.
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(token)) })
	http.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) { w.Write(pubkey) })

	server := http.Server{Addr: serverAddr}
	fmt.Printf("📎 Token now available under https://%s/token\n", serverAddr)
	fmt.Printf("👂 Listening on https://%s/pubkey for secrets...\n", serverAddr)
	err = server.ListenAndServe()
	fmt.Println(err)
}
