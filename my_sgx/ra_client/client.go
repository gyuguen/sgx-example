package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/edgelesssys/ego/eclient"
	"os"
)

func main() {
	reportBase64 := os.Args[1]
	if reportBase64 == "" {
		panic(errors.New("you should be input {report} {pubkey}"))
	}

	fmt.Println(fmt.Sprintf("reportBase64: %v",reportBase64))

	reportBytes, err := base64.StdEncoding.DecodeString(reportBase64)
	if err != nil {
		panic(err)
	}


	signerID := flag.String("signerID", "", "signer ID")
	pubkey := flag.String("pubkey", "", "PubKey")
	flag.Parsed()

	fmt.Println(fmt.Sprintf("signerID: %v",signerID))
	fmt.Println(fmt.Sprintf("pubkey: %v",pubkey))

	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		panic(err)
	}

	signerIDBytes, err := hex.DecodeString(*signerID)
	if err != nil {
		panic(err)
	}

	pubkeyBytes, err := base64.StdEncoding.DecodeString(*pubkey)
	if err != nil {
		panic(err)
	}

	fmt.Println("#### Report ####")
	fmt.Println(fmt.Sprintf("SignerId: %v", hex.EncodeToString(report.SignerID)))
	fmt.Println(fmt.Sprintf("TCBStatus: %v", report.TCBStatus))
	fmt.Println(fmt.Sprintf("UniqueID: %v", hex.EncodeToString(report.UniqueID)))
	fmt.Println(fmt.Sprintf("ProductID: %v", binary.LittleEndian.Uint16(report.ProductID)))
	fmt.Println(fmt.Sprintf("PubKey: %v", base64.StdEncoding.EncodeToString(report.Data)))

	fmt.Println("")
	fmt.Println("Check report value")
	if !bytes.Equal(signerIDBytes, report.SignerID[:len(signerIDBytes)]) {
		panic(errors.New("report data does not match the signerID"))
	}
	if !bytes.Equal(pubkeyBytes, report.Data[:len(pubkeyBytes)]) {
		panic(errors.New("report data does not match the pubkey"))
	}
	if report.SecurityVersion != 3 {
		panic(errors.New("security version does not match the certificate's version"))
	}
	if binary.LittleEndian.Uint16(report.ProductID) != 111 {
		panic(errors.New("productID does not match the certificate's productId"))
	}
}
