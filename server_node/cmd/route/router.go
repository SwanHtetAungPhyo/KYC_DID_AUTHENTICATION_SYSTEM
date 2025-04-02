package route

import (
	"github.com/SwanHtetAungPhyo/server_node/internal/handler"
	"github.com/SwanHtetAungPhyo/server_node/internal/services"
	"github.com/SwanHtetAungPhyo/server_node/pkg/utils"
	"github.com/fasthttp/router"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func SetUpRoutes() *router.Router {
	routeLog := utils.GetLogger()
	routeLog.WithFields(logrus.Fields{
		"routes": "SetUpRoutes",
	}).Info("Setting up routes..")
	routers := router.New()
	routers.GET("/", func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("text/html")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody([]byte("<h1>Hello World</h1>"))
	})

	services := services.NewDidService(routeLog)
	handlers := handler.NewDidHandler(routeLog, services)
	routers.POST("/registry", handlers.RegistryHandler)
	return routers
}
