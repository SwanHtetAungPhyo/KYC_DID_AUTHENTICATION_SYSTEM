package util

import (
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

type Response struct {
	Message  string `json:"message,omitempty"`
	FilePath string `json:"filePath,omitempty"`
	Error    string `json:"error,omitempty"`
	Data     any    `json:"data,omitempty"`
}

func JSONResponse(ctx *fasthttp.RequestCtx, statusCode int, response Response) {
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")

	responseJSON, err := json.Marshal(response)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"error": "Failed to encode JSON response"}`))
		return
	}

	ctx.SetBody(responseJSON)
}
