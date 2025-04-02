package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/SwanHtetAungPhyo/server_node/internal/model"
	"github.com/SwanHtetAungPhyo/server_node/internal/services"
	"github.com/SwanHtetAungPhyo/server_node/pkg/utils"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type DidHandlerInterface interface {
	RegistryHandler(ctx *fasthttp.RequestCtx)
	AuthHandler(ctx *fasthttp.RequestCtx)
}
type serverResp struct {
	DID      string            `json:"did"`
	Services map[string]string `json:"services"`
}
type DidHandler struct {
	log     *logrus.Logger
	service *services.DidService
}

func NewDidHandler(log *logrus.Logger, service *services.DidService) *DidHandler {
	return &DidHandler{
		log:     log,
		service: service,
	}
}

func (d *DidHandler) RegistryHandler(ctx *fasthttp.RequestCtx) {
	var req model.ReqToServer
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetContentType("application/json")
		ctx.SetBody([]byte(err.Error()))
		utils.SendErrorResponse(ctx, errors.New(fmt.Sprint("Incorrect request body: ", string(ctx.PostBody()))))
	}
	did, condition := d.service.AuthAndGenerateDID(req)
	if !condition {
		utils.SendErrorResponse(ctx, errors.New("invalid request"))
		return
	}

	if did == "" {
		utils.SendErrorResponse(ctx, errors.New("DID is empty"))
		return
	}

	var resp serverResp
	resp.DID = did
	resp.Services = make(map[string]string)
	resp.Services["DID"] = did
	utils.JsonResponse(ctx, 200, "success", resp)
	return

}

func (d *DidHandler) AuthHandler(ctx *fasthttp.RequestCtx) {
	//TODO implement me
	panic("implement me")
}
