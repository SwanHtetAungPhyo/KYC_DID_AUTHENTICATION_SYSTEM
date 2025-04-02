package utils

import (
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JsonResponse Send JSON response with proper headers
func JsonResponse(ctx *fasthttp.RequestCtx, status int, msg string, data interface{}) {
	ctx.SetStatusCode(status)
	ctx.Response.Header.Set("Content-Type", "application/json")
	setCORSHeaders(ctx)

	response := Response{Status: status, Message: msg, Data: data}
	if jsonData, err := json.Marshal(response); err == nil {
		ctx.SetBody(jsonData)
	} else {
		SendErrorResponse(ctx, err)
	}
}

// Handle JSON marshaling errors
func SendErrorResponse(ctx *fasthttp.RequestCtx, err error) {
	ctx.SetStatusCode(500)
	errorResponse := Response{Status: 500, Message: err.Error()}
	if jsonData, _ := json.Marshal(errorResponse); jsonData != nil {
		ctx.SetBody(jsonData)
	}
}

// Set CORS headers
func setCORSHeaders(ctx *fasthttp.RequestCtx) {
	headers := ctx.Response.Header
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	headers.Set("Access-Control-Allow-Headers", "Content-Type")
	headers.Set("Access-Control-Allow-Credentials", "true")
	headers.Set("Access-Control-Max-Age", "86400")
}
