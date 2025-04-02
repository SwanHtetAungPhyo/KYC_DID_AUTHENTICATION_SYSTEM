package services

import (
	"encoding/hex"
	"fmt"
	"github.com/SwanHtetAungPhyo/server_node/internal/model"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"log"

	"github.com/sirupsen/logrus"
)

type DidMethods interface {
	AuthAndGenerateDID(req model.FinalRegistration) string
}
type DidService struct {
	logger *logrus.Logger
}

func NewDidService(logger *logrus.Logger) *DidService {
	return &DidService{logger: logger}

}

func (d *DidService) AuthAndGenerateDID(req model.ReqToServer) (string, bool) {
	// ✅ Decode Public Key from Hex
	log.Printf("Received DIDHASH (server): %s", req.Registration.DIDHASH)

	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		fmt.Println("Failed to decode public key:", err)
		return "", false
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		return "", false
	}
	_ = pubKey

	hashBytes, err := base58.Decode(req.Registration.DIDHASH)
	if err != nil {
		fmt.Println("Failed to decode hash:", err)
		return "", false
	}

	log.Printf("Decoded hashBytes (server): %x", hashBytes)
	signatureBytes, err := base58.Decode(req.Signature)
	if err != nil {
		fmt.Println("Failed to decode signature:", err)
		return "1", false
	}

	// ✅ Prepare Signature for Verification (remove V byte)
	if len(signatureBytes) != 65 {
		fmt.Println("Invalid signature length")
		return "1", false
	}
	signatureWithoutV := signatureBytes[:64]

	// ✅ Verify Signature
	isValid := crypto.VerifySignature(pubKeyBytes, hashBytes, signatureWithoutV)
	if !isValid {
		fmt.Println("Signature verification failed")
		return "1", false
	}

	log.Println("✅ Signature verified successfully")
	did := "did:kyc:" + base58.Encode(hashBytes)
	log.Println(did)
	return did, true
}
