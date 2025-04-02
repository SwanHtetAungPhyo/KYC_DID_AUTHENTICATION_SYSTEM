package handler

import (
	"github.com/SwanHtetAungPhyo/nigga/internal/cryptography"
	"github.com/SwanHtetAungPhyo/nigga/internal/model"
	"github.com/SwanHtetAungPhyo/nigga/internal/services"
	"github.com/SwanHtetAungPhyo/nigga/internal/util"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
	"log"
)

type HandlerImpl struct {
	service services.ServicesImpl
}

func NewHandler(service services.ServicesImpl) *HandlerImpl {
	return &HandlerImpl{service: service}
}

func (h *HandlerImpl) AccountGeneration(ctx *fasthttp.RequestCtx) {
	var req model.RequestBody
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil || req.Password == "" {
		log.Printf("AccountGeneration - Invalid JSON or missing 'password': %v", err)
		util.JSONResponse(ctx, fasthttp.StatusBadRequest, util.Response{Error: "Invalid JSON or missing 'password'"})
		return
	}

	log.Printf("AccountGeneration - Request: %v", req)
	filePath, err := h.service.GenerateWalletService(req.Password)
	if err != nil {
		log.Printf("AccountGeneration - Failed to generate wallet: %v", err)
		util.JSONResponse(ctx, fasthttp.StatusInternalServerError, util.Response{Error: "Failed to generate wallet"})
		return
	}

	log.Printf("AccountGeneration - Wallet created successfully, file path: %s", filePath)
	util.JSONResponse(ctx, fasthttp.StatusOK, util.Response{
		Message:  "Wallet created successfully",
		FilePath: filePath,
	})
}

func (h *HandlerImpl) GetAccountInfo(ctx *fasthttp.RequestCtx) {
	var req model.RequestBody
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil || req.Password == "" {
		log.Printf("GetAccountInfo - Invalid JSON or missing 'password': %v", err)
		util.JSONResponse(ctx, fasthttp.StatusBadRequest, util.Response{Error: "Invalid JSON or missing 'password'"})
		return
	}

	log.Printf("GetAccountInfo - Request: %v", req)
	userLocalAccount, err := h.service.GetAccountService(req.Password)
	if err != nil {
		log.Printf("GetAccountInfo - Failed to get account info: %v", err)
		util.JSONResponse(ctx, fasthttp.StatusInternalServerError, util.Response{
			Message: "Failed to get account info because of invalid Password",
			Error:   "Failed to get account info",
		})
		return
	}

	if userLocalAccount == "" {
		log.Println("GetAccountInfo - Account info not found")
		util.JSONResponse(ctx, fasthttp.StatusNotFound, util.Response{Error: "Account info not found"})
		return
	}

	log.Printf("GetAccountInfo - Account info retrieved successfully: %v", userLocalAccount)
	util.JSONResponse(ctx, fasthttp.StatusOK, util.Response{
		Message: "Account info retrieved successfully",
		Data:    []interface{}{userLocalAccount},
	})
}

func (h *HandlerImpl) CreatAccountLocalAndSendToServer(ctx *fasthttp.RequestCtx) {
	var req model.RequestBody
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil || req.Password == "" {
		log.Printf("CreatAccountLocalAndSendToServer - Invalid JSON or missing 'password': %v", err)
		util.JSONResponse(ctx, fasthttp.StatusBadRequest, util.Response{Error: "Invalid JSON or missing 'password'"})
		return
	}

	log.Printf("CreatAccountLocalAndSendToServer - Request: %v", req)
	err := h.service.StoreInKeyChain(req)
	if err != nil {
		log.Printf("CreatAccountLocalAndSendToServer - Failed to save account info: %v", err)
		util.JSONResponse(ctx, fasthttp.StatusInternalServerError, util.Response{
			Message: "Failed to save account info",
		})
		return
	}

	log.Println("CreatAccountLocalAndSendToServer - Account info saved successfully")
	util.JSONResponse(ctx, fasthttp.StatusOK, util.Response{
		Message: "Account info saved successfully",
	})
}

func (h *HandlerImpl) Login(ctx *fasthttp.RequestCtx) {
	var req model.RequestBody
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil || req.Password == "" {
		log.Printf("Login - Invalid JSON or missing 'password': %v", err)
		util.JSONResponse(ctx, fasthttp.StatusBadRequest, util.Response{Error: "Invalid JSON or missing 'password'"})
		return
	}

	log.Printf("Login - Request: %v", req)
	booleanCondition, err := h.service.AuthenticationFromKeyChain(req.Email, req.Password)
	if err != nil {
		log.Printf("Login - Failed to authenticate: %v", err)
		util.JSONResponse(ctx, fasthttp.StatusInternalServerError, util.Response{
			Message: "Failed to authenticate",
			Error:   err.Error(),
		})
		return
	}
	if !booleanCondition {
		log.Println("Login - Authentication failed")
		util.JSONResponse(ctx, fasthttp.StatusUnauthorized, util.Response{Error: "Authentication failed"})
		return
	}

	log.Printf("Login - Login successful for user: %s", req.FullName)
	util.JSONResponse(ctx, fasthttp.StatusOK, util.Response{
		Message: "Login successful",
		Data:    []interface{}{req.FullName},
	})
}

func (h *HandlerImpl) CreateDID(ctx *fasthttp.RequestCtx) {
	var req model.RequestBody
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil || req.Password == "" {
		log.Printf("CreateDID - Invalid JSON or missing 'password': %v", err)
		util.JSONResponse(ctx, fasthttp.StatusBadRequest, util.Response{Error: "Invalid JSON or missing 'password'"})
		return
	}

	log.Printf("CreateDID - Request: %v", req)
	loadAccount, err := cryptography.LoadFromLocalWithPassword(req.Password)
	if err != nil {
		log.Printf("CreateDID - Failed to load account: %v", err)
		util.JSONResponse(ctx, fasthttp.StatusInternalServerError, util.Response{
			Message: "Failed to create DID",
		})
		return
	}

	did, err := cryptography.CreateDID(loadAccount, req.Biometric, req.NationalID)
	if err != nil {
		log.Printf("CreateDID - Failed to create DID: %v", err)
		util.JSONResponse(ctx, fasthttp.StatusInternalServerError, util.Response{
			Message: "Failed to create DID",
		})
		return
	}

	log.Printf("CreateDID - DID created successfully: DID=%s", did)
	util.JSONResponse(ctx, fasthttp.StatusOK, util.Response{
		Message: "DID created successfully",
		Data: []interface{}{
			did,
		},
	})
}
