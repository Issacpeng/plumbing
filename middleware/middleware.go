package middleware

import (
	"github.com/containerops/plumbing/setting"
	"gopkg.in/macaron.v1"
)

func SetMiddlewares(m *macaron.Macaron) {
	//Set static file directory,static file access without log output
	m.Use(macaron.Static("external", macaron.StaticOptions{
		Expires: func() string { return "max-age=0" },
	}))

	InitLog(setting.RunMode, setting.LogPath)

	//Set global Logger
	m.Map(Log)
	//Set logger handler function, deal with all the Request log output
	m.Use(logger(setting.RunMode))
	//Set recovery handler to returns a middleware that recovers from any panics
	m.Use(macaron.Recovery())
}
