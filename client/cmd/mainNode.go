package cmd

import (
	"github.com/SwanHtetAungPhyo/kycdid/internal/handler"
	"github.com/SwanHtetAungPhyo/kycdid/internal/services"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func Start(port string) {
	routers := router.New()

	service := services.NewServicesImpl()
	handle := handler.NewHandler(*service)
	middleWareSetup(routers.Handler)
	routers.POST("/createAccount", handle.AccountGeneration)
	routers.POST("/getAccount", handle.GetAccountInfo)
	routers.POST("/register", handle.CreatAccountLocalAndSendToServer)
	routers.POST("/login", handle.Login)
	routers.POST("/did", handle.CreateDID)
	server := &fasthttp.Server{
		Handler: routers.Handler,
		Name:    "niggo",
	}
	go func() {
		log.Printf("Listening on port %s", port)
		if err := server.ListenAndServe(port); err != nil {
			log.Fatalf("Error in ListenAndServe: %s", err)
		}
	}()

	osChan := make(chan os.Signal, 1)
	signal.Notify(osChan, syscall.SIGINT, syscall.SIGTERM)
	<-osChan

	if err := server.Shutdown(); err != nil {
		log.Fatalf("Error in Shutdown: %s", err)
	}
}

func middleWareSetup(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("%s %s %s", ctx.Method(), ctx.RequestURI(), ctx.RemoteIP())
		next(ctx)
	}
}
