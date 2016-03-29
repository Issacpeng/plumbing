package web

import (
	"gopkg.in/macaron.v1"

	"github.com/containerops/plumbing/middleware"
	"github.com/containerops/plumbing/router"
)

func SetPlumbingMacaron(m *macaron.Macaron) {
	//Setting Middleware
	middleware.SetMiddlewares(m)

	//Setting Router
	router.SetRouters(m)
}
