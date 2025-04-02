package model

type (
	DIDRegistryByUser struct {
		NationalIDHash string `json:"national_id_hash"`
		BiometricHash  string `json:"biometric_hash"`
		BiometricSalt  string `json:"biometric_salt"`
		CreatedTime    string `json:"created_time"`
		PublicKey      string `json:"public_key"`
	}
	Resp struct {
		DID      string            `json:"did"`
		Services map[string]string `json:"services"`
	}
	ReqToServer struct {
		Registration FinalRegistration `json:"registration"`
		PublicKey    string            `json:"public_key"`
		Signature    string            `json:"signature"`
	}
	FinalRegistration struct {
		DIDHASH     string `json:"did_hash"`
		CreatedTime string `json:"created"`
		PublicKey   string `json:"public_key"`
		Signature   string `json:"signature"`
	}
)
