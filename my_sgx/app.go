package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	case "get-report":
		getReport()
	case "verify-report":
		verifyReport()
	case "make-encrypt-data":
		makeEncryptData()
	case "decrypt-data":
		decryptData()
	default:
		panic("command is invalid.(check-path, create-key, get-pubkey, get-report, verify-report)")
	}
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
	privKeyBytes := getPrivkeyFromSeal()

	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	fmt.Println(base64.StdEncoding.EncodeToString(pubKey.SerializeCompressed()))
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

func getReport() {
	pubkeyBase64 := os.Args[2]
	if pubkeyBase64 == "" {
		panic(errors.New("pubkey is empty"))
	}
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkeyBase64)
	if err != nil {
		panic(err)
	}

	reportBytes, err := enclave.GetRemoteReport(pubkeyBytes)
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(reportBytes))
}

func verifyReport() {
	reportBase64 := os.Args[2]
	if reportBase64 == "" {
		panic(errors.New("you should be input {report} {pubkey}"))
	}

	pubkeyBase64 := os.Args[3]
	if pubkeyBase64 == "" {
		panic(errors.New("you should be input {report} {pubkey}"))
	}

	reportBytes, err := base64.StdEncoding.DecodeString(reportBase64)
	if err != nil {
		panic(err)
	}

	report, err := enclave.VerifyRemoteReport(reportBytes)
	if err != nil {
		panic(err)
	}

	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkeyBase64)
	if err != nil {
		panic(err)
	}

	fmt.Println("## Report ##")
	fmt.Println(fmt.Sprintf("SignerId: %s", hex.EncodeToString(report.SignerID)))
	fmt.Println(fmt.Sprintf("TCBStatus: %s", report.TCBStatus))
	fmt.Println(fmt.Sprintf("UniqueID: %s", base64.StdEncoding.EncodeToString(report.UniqueID)))

	fmt.Println("## pubkey verification ##")
	fmt.Println(fmt.Sprintf("Pubkey: %s", base64.StdEncoding.EncodeToString(report.Data[:len(pubkeyBytes)])))
	if !bytes.Equal(pubkeyBytes, report.Data[:len(pubkeyBytes)]) {
		panic(errors.New("report data does not match the certificate's hash"))
	}
	fmt.Println("success")

	fmt.Println("## security version verification ##")
	fmt.Println(fmt.Sprintf("SecurityVersion: %v", report.SecurityVersion))
	if report.SecurityVersion != 3 {
		panic(errors.New("security version does not match the certificate's version"))
	}
	fmt.Println("success")

	fmt.Println("## productID verification ##")
	fmt.Println(fmt.Sprintf("ProductID: %v", binary.LittleEndian.Uint16(report.ProductID)))
	if binary.LittleEndian.Uint16(report.ProductID) != 111 {
		panic(errors.New("productID does not match the certificate's productId"))
	}
	fmt.Println("success!!")
}

func makeEncryptData() {
	plainText := os.Args[2]
	if plainText == "" {
		panic(errors.New("you should be input {text} {pubkey}"))
	}
	pubkeyBase64 := os.Args[3]
	if pubkeyBase64 == "" {
		panic(errors.New("pubkey is empty"))
	}
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkeyBase64)
	if err != nil {
		panic(err)
	}

	encBytes, err := crypto.EncryptData(pubkeyBytes, []byte(plainText))
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encBytes))
}

func decryptData() {
	cipherTextBase64 := os.Args[2]
	if cipherTextBase64 == "" {
		panic(errors.New("cipherText is empty"))
	}

	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		panic(err)
	}

	privKeyBytes := getPrivkeyFromSeal()
	privkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)

	plainTextBytes, err := btcec.Decrypt(privkey, cipherTextBytes)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plainTextBytes))
}
