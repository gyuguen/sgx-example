package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/edgelesssys/ego/attestation"
	"io/ioutil"
	"net/http"
)

const attestationProviderURL = "https://shareduks.uks.attest.azure.net"

func main() {
	serverAddr := flag.String("a", "localhost:8080", "server address")
	flag.Parse()

	serverURL := "https://" + *serverAddr
	tokenBytes := httpGet(serverURL + "/token")
	fmt.Printf("🆗 Loaded server attestation token from %s.\n", serverURL+"/token")

	report, err := attestation.VerifyAzureAttestationToken(string(tokenBytes), attestationProviderURL)
	if err != nil {
		panic(err)
	}

	fmt.Println("✅ Azure Attestation Token verified.")

	// Verify the report. ProductID, SecurityVersion and Debug were defined in
	// the enclave.json, and included in the servers binary.
	if err := verifyReportValues(report); err != nil {
		panic(err)
	}

}

func verifyReportValues(report attestation.Report) error {
	fmt.Println("## Report ##")
	fmt.Println(fmt.Sprintf("SignerId: %s", hex.EncodeToString(report.SignerID)))
	fmt.Println(fmt.Sprintf("TCBStatus: %s", report.TCBStatus))
	fmt.Println(fmt.Sprintf("UniqueID: %s", hex.EncodeToString(report.UniqueID)))
	fmt.Println(fmt.Sprintf("ProductID: %v", binary.LittleEndian.Uint16(report.ProductID)))
	fmt.Println(fmt.Sprintf("SecurityVersion: %v", report.SecurityVersion))
	fmt.Println(fmt.Sprintf("Pubkey: %s", base64.StdEncoding.EncodeToString(report.Data[:32])))

	// For production, you must also verify that report.Debug == false

	return nil
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
