package router

import (
	"gopkg.in/macaron.v1"

	"github.com/containerops/plumbing/handler"
)

func SetRouters(m *macaron.Macaron) {
	m.Get("/", handler.IndexHandler)
}
