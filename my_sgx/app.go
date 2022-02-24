package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"github.com/gyuguen/sgx/my_sgx/crypto"
	"io/ioutil"
	"os"
	"path/filepath"
)

var myPrivKey = crypto.Hash([]byte("my_priv_key"))
var defaultSealPath = "/data/.sgx_seel/my_priv_key.seal"

func main() {
	switch os.Args[1] {
	case "check-path":
		checkPath()
	case "create-key":
		createKey()
	case "get-pubkey":
		getPubkey()
	default:
		panic("command is invalid.(check-path, create-key, get-pubkey)")
	}

	/*reportBytes, err := enclave.GetRemoteReport(pubKey.SerializeCompressed())

	if err != nil {
		panic(err)
	}

	if err := verifyReport(reportBytes, pubKey.SerializeCompressed()); err != nil {
		panic(err)
	}*/

	//encText := getEncTextFromExternal()

}

func checkPath() {
	targetDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	fmt.Println(fmt.Sprintf("Path: %v", targetDir))

	files, err := ioutil.ReadDir(targetDir)
	if err != nil {
		panic(err)
	}
	fmt.Println(fmt.Sprintf("Files: %v", files))
}

func createKey() {
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

func getPubkey() {
	file, err := ioutil.ReadFile(defaultSealPath)
	if err != nil {
		panic(fmt.Errorf("you have to run 'create-key' first. %e", err))
	}

	privKeyBytes, err := ecrypto.Decrypt(file, myPrivKey, nil)
	if err != nil {
		panic(err)
	}

	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	fmt.Println(base64.StdEncoding.EncodeToString(pubKey.SerializeCompressed()))
}

func verifyReport(reportBytes []byte, pubKey []byte) error {
	report, err := enclave.VerifyRemoteReport(reportBytes)

	if err != nil {
		return err
	}

	fmt.Println(string(report.SignerID))
	fmt.Println(pubKey)
	fmt.Println(report.Data[:len(pubKey)])
	fmt.Println(report.TCBStatus)

	if !bytes.Equal(pubKey, report.Data[:len(pubKey)]) {
		return errors.New("report data does not match the certificate's hash")
	}

	if report.SecurityVersion != 3 {
		return errors.New("security version does not match the certificate's version")
	}

	if binary.LittleEndian.Uint16(report.ProductID) != 111 {
		return errors.New("security version does not match the certificate's productId")
	}

	return nil
}
