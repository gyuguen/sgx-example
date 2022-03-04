package main

import (
	"encoding/base64"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/ecrypto"
	handler2 "github.com/gyuguen/sgx/my_server/handler"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const (
	serverAddr      = "0.0.0.0:8080"
	defaultSealPath = "/data/.sgx_seel/my_priv_key.seal"
)

var myPrivKey = []byte("my_priv_key")

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

		encPriv, err := ecrypto.Encrypt(privKey.Serialize(), myPrivKey, nil)
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

	privKeyBytes, err := ecrypto.Decrypt(file, myPrivKey, nil)
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

	// Create HTTPS server.
	http.Handle("/token", handler2.NewTokenHandler(pubkey))
	http.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) { w.Write(pubkey) })
	http.Handle("/report", handler2.NewReportHandler(pubkey))
	http.Handle("/remote-report-verify", handler2.NewReportHandler(pubkey))

	server := http.Server{Addr: serverAddr}
	fmt.Printf("📎 Token now available under https://%s/token\n", serverAddr)
	fmt.Printf("👂 Listening on https://%s/pubkey for secrets...\n", serverAddr)
	err := server.ListenAndServe()
	fmt.Println(err)
}

func HttpGet(url string) []byte {
	client := http.Client{}
	resp, err := client.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		panic(resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return body
}
