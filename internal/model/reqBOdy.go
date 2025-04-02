package model

const (
	ServiceName = "DIDRegistry"
)

type RequestBody struct {
	FullName   string `json:"full_name,omitempty"`
	Email      string `json:"email,omitempty"`
	Password   string `json:"password,omitempty"`
	Biometric  string `json:"biometric,omitempty"`
	NationalID string `json:"national,omitempty"`
}
