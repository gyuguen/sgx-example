package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/edgelesssys/ego/attestation"
	"github.com/gyuguen/sgx/my_server/types"
	"io/ioutil"
	"net/http"
)

func main() {
	serverAddr := flag.String("a", "20.212.166.103:8080", "server address")
	flag.Parse()

	serverURL := "http://" + *serverAddr
	tokenBytes := httpGet(serverURL + "/token")
	fmt.Printf("🆗 Loaded server attestation token from %s.\n", serverURL+"/token")

	report, err := attestation.VerifyAzureAttestationToken(string(tokenBytes), types.AttestationProviderURL)
	if err != nil {
		panic(err)
	}

	fmt.Println("✅ Azure Attestation Token verified.")

	verifyReportValues(report)

	pubkeyBytes := httpGet(serverURL + "/pubkey")
	fmt.Printf("Server Pubkey: %s", base64.StdEncoding.EncodeToString(pubkeyBytes))

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
