package handler

import (
	"github.com/edgelesssys/ego/enclave"
	"github.com/gyuguen/sgx/my_server/types"
	"net/http"
)

type TokenHandler struct {
	Token string
}

func NewTokenHandler(pubkey []byte) TokenHandler {
	token, err := enclave.CreateAzureAttestationToken(pubkey, types.AttestationProviderURL)
	if err != nil {
		panic(err)
	}

	return TokenHandler{Token: token}
}

func (v TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(v.Token))
}
