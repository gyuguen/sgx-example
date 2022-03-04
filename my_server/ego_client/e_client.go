package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/eclient"
	"io/ioutil"
	"net/http"
)

func main() {
	serverAddr := flag.String("a", "localhost:8080", "server address")
	flag.Parse()

	serverURL := "http://" + *serverAddr

	reportBytes := httpGet(serverURL + "/report")

	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		panic(err)
	}

	verifyReportValues(report)
}

func verifyReportValues(report attestation.Report) {
	fmt.Println("## Report ##")
	fmt.Println(fmt.Sprintf("SignerId: %s", hex.EncodeToString(report.SignerID)))
	fmt.Println(fmt.Sprintf("TCBStatus: %s", report.TCBStatus))
	fmt.Println(fmt.Sprintf("UniqueID: %s", hex.EncodeToString(report.UniqueID)))
	fmt.Println(fmt.Sprintf("ProductID: %v", binary.LittleEndian.Uint16(report.ProductID)))
	fmt.Println(fmt.Sprintf("SecurityVersion: %v", report.SecurityVersion))
	fmt.Println(fmt.Sprintf("Pubkey: %s", base64.StdEncoding.EncodeToString(report.Data)))
}

func httpGet(url string) []byte {
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