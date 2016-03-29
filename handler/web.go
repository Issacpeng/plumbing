package handler

import (
	"encoding/json"
	"net/http"

	"gopkg.in/macaron.v1"
)

func IndexHandler(ctx *macaron.Context) (int, []byte) {
	result, _ := json.Marshal(map[string]string{"message": "Plumbing - Git Backend Storage Engine"})

	return http.StatusOK, result
}
