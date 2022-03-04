package handler

import (
	"github.com/edgelesssys/ego/enclave"
	"net/http"
)

type ReportHandler struct {
	Pubkey []byte
}

func NewReportHandler(pubkey []byte) ReportHandler {
	return ReportHandler{Pubkey: pubkey}
}

func (v ReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reportBytes, err := enclave.GetRemoteReport(v.Pubkey)
	if err != nil {
		panic(err)
	}

	w.Write(reportBytes)
}
