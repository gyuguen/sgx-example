package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/eclient"
	"github.com/edgelesssys/ego/enclave"
)

func main() {
	privKey, err := btcec.NewPrivateKey(btcec.S256())

	if err != nil {
		panic(err)
	}

	pubKey := privKey.PubKey().SerializeCompressed()

	reportBytes, err := enclave.GetRemoteReport(pubKey)

	if err != nil {
		panic(err)
	}

	if err := verifyReport(reportBytes, pubKey); err != nil {
		panic(err)
	}

}

func verifyReport(reportBytes []byte, pubKey []byte) error {
	report, err := eclient.VerifyRemoteReport(reportBytes)

	if err != nil {
		return err
	}

	fmt.Println(report)

	if !bytes.Equal(pubKey, report.Data) {
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
