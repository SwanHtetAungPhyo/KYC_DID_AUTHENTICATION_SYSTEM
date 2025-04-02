package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

const (
	minPasswordLen    = 12
	challengeSize     = 32
	biometricSaltSize = 32
	biometricN        = 32768
	biometricr        = 8
	biometricp        = 1
	argonTime         = 6
	argonMemory       = 256 * 1024
	argonThreads      = 4
	argonKeyLen       = 32
	url               = "https://localhost:443/registry"
)

type UserAccountLocal struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
	Address    string
}

type ChallengeRecord struct {
	Value      []byte
	DID        string
	ExpiresAt  time.Time
	ClientIP   string
	UsageCount int
}

type OnChain struct {
	Did      string                 `json:"did"`
	Services map[string]interface{} `json:"services"`
}

var OnChainStorage = make([]OnChain, 0)

func AddToOnChain(onChain OnChain) {
	OnChainStorage = append(OnChainStorage, onChain)
}

func GetOnChainData(did string) *OnChain {
	return &OnChainStorage[0]
}

type DIDRegistryByUser struct {
	NationalIDHash string `json:"national_id_hash"`
	BiometricHash  string `json:"biometric_hash"`
	BiometricSalt  string `json:"biometric_salt"`
	CreatedTime    string `json:"created_time"`
	PublicKey      string `json:"public_key"`
}

type FinalRegistration struct {
	DIDHASH     string `json:"did_hash"`
	CreatedTime string `json:"created"`
	PublicKey   string `json:"public_key"`
}
type ECDSASignature struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}

type DIDAuthentication struct {
	DID       string         `json:"did"`
	Challenge string         `json:"challenge"`
	Signature ECDSASignature `json:"signature"`
	PublicKey string         `json:"public_key"`
	Timestamp int64
}

type ServerResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Data    struct {
		DID      string            `json:"did"`
		Services map[string]string `json:"services"`
	} `json:"data"`
}

var challengeStore = struct {
	sync.RWMutex
	store map[string]ChallengeRecord
}{store: make(map[string]ChallengeRecord)}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return errors.New("password must be at least 12 characters")
	}
	return nil
}

func KeyGeneration() UserAccountLocal {
	privateKey, err := crypto.GenerateKey()
	failOnError(err, "Error generating private key")

	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	return UserAccountLocal{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
	}
}

func deriveKeys(password string, salt []byte) (encKey, hmacKey []byte) {
	baseKey := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen*2)
	return baseKey[:argonKeyLen], baseKey[argonKeyLen:]
}

func SaveToLocalWithPassword(userAccLocal UserAccountLocal, password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}

	privateKeyBytes := crypto.FromECDSA(userAccLocal.PrivateKey)
	publicKeyBytes := userAccLocal.PublicKey

	persist := struct {
		PrivateKeyB58 string `json:"private_key"`
		PublicKeyB58  string `json:"public_key"`
		Address       string `json:"address"`
	}{
		base58.Encode(privateKeyBytes),
		base58.Encode(publicKeyBytes),
		userAccLocal.Address,
	}

	plainData, err := json.Marshal(persist)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}

	encKey, hmacKey := deriveKeys(password, salt)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("AES init failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM init failed: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	encryptedData := aesGCM.Seal(nil, nonce, plainData, nil)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encryptedData)
	finalPayload := append(mac.Sum(nil), encryptedData...)

	storage := struct {
		Salt       []byte `json:"salt"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}{
		salt, nonce, finalPayload,
	}

	fileData, err := json.Marshal(storage)
	if err != nil {
		return "", fmt.Errorf("storage marshal failed: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	failOnError(err, "Error getting home directory")
	filePath := filepath.Join(homeDir, ".keystore")
	if err := os.WriteFile(filePath, fileData, 0600); err != nil {
		return "", fmt.Errorf("file write failed: %w", err)
	}
	return filePath, nil
}

func LoadFromLocalWithPassword(password string) (UserAccountLocal, error) {
	homeDir, err := os.UserHomeDir()
	failOnError(err, "Error getting home directory")
	fileData, err := os.ReadFile(filepath.Join(homeDir, ".keystore"))
	if err != nil {
		return UserAccountLocal{}, fmt.Errorf("file read failed: %w", err)
	}

	var storage struct {
		Salt       []byte `json:"salt"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(fileData, &storage); err != nil {
		return UserAccountLocal{}, fmt.Errorf("storage parsing failed: %w", err)
	}

	encKey, hmacKey := deriveKeys(password, storage.Salt)

	if len(storage.Ciphertext) < sha256.Size {
		return UserAccountLocal{}, errors.New("invalid ciphertext length")
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(storage.Ciphertext[sha256.Size:])
	if !hmac.Equal(mac.Sum(nil), storage.Ciphertext[:sha256.Size]) {
		return UserAccountLocal{}, errors.New("invalid HMAC")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return UserAccountLocal{}, fmt.Errorf("aes creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return UserAccountLocal{}, fmt.Errorf("gcm creation failed: %w", err)
	}

	plainData, err := aesGCM.Open(nil, storage.Nonce, storage.Ciphertext[sha256.Size:], nil)
	if err != nil {
		return UserAccountLocal{}, fmt.Errorf("decryption failed: %w", err)
	}

	var persist struct {
		PrivateKeyB58 string `json:"private_key"`
		PublicKeyB58  string `json:"public_key"`
		Address       string `json:"address"`
	}
	if err := json.Unmarshal(plainData, &persist); err != nil {
		return UserAccountLocal{}, fmt.Errorf("data parsing failed: %w", err)
	}

	privateKeyBytes, err := base58.Decode(persist.PrivateKeyB58)
	if err != nil {
		return UserAccountLocal{}, fmt.Errorf("base58 decode private key failed: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return UserAccountLocal{}, fmt.Errorf("ecdsa parsing failed: %w", err)
	}

	defer func() {
		for i := range plainData {
			plainData[i] = 0
		}
	}()

	return UserAccountLocal{
		PrivateKey: privateKey,
		PublicKey:  crypto.FromECDSAPub(&privateKey.PublicKey),
		Address:    persist.Address,
	}, nil
}

func CreateDID(account UserAccountLocal, biometric string, nationalID string) (*ServerResponse, error) {
	if nationalID == "" {
		return &ServerResponse{}, errors.New("national ID not configured")
	}

	reader := hkdf.New(sha256.New, crypto.FromECDSA(account.PrivateKey), nil, nil)
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, hmacKey); err != nil {
		return &ServerResponse{}, fmt.Errorf("hmac key derivation failed: %w", err)
	}

	biometricSalt := make([]byte, biometricSaltSize)
	if _, err := rand.Read(biometricSalt); err != nil {
		return &ServerResponse{}, fmt.Errorf("biometric salt failed: %w", err)
	}

	biometricHash, err := hashBiometric(biometric, biometricSalt)
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("biometric hashing failed: %w", err)
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(nationalID))
	nationalIDHash := base58.Encode(mac.Sum(nil))
	registry := DIDRegistryByUser{
		NationalIDHash: nationalIDHash,
		BiometricHash:  base58.Encode(biometricHash),
		BiometricSalt:  base58.Encode(biometricSalt),
		CreatedTime:    time.Now().UTC().Format(time.RFC3339),
		PublicKey:      base58.Encode(crypto.FromECDSAPub(&account.PrivateKey.PublicKey)),
	}

	dataBytes, err := json.Marshal(registry)
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("json marshaling failed: %w", err)
	}

	signatureByte, err := hashSign(dataBytes, account.PrivateKey)
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("hashing failed: %w", err)
	}
	signature := base58.Encode(signatureByte)
	resp, err := sendToServerNode(signature, registry, account.PrivateKey)
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("sending to server failed: %w", err)
	}
	return resp, nil
}

func hashSign(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := secp256k1.Sign(hash[:], crypto.FromECDSA(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	return sig, nil
}

func sendToServerNode(signatureBase58 string, registry DIDRegistryByUser, privateKey *ecdsa.PrivateKey) (*ServerResponse, error) {
	var reqToServer struct {
		Registration FinalRegistration `json:"registration"`
		PublicKey    string            `json:"public_key"`
		Signature    string            `json:"signature"`
	}
	var serverResp struct {
		DID      string            `json:"did"`
		Services map[string]string `json:"services"`
	}

	// ✅ Step 1: Concatenate Data for Hashing
	hashData := fmt.Sprintf("%s%s%s%s%s",
		registry.NationalIDHash,
		registry.BiometricHash,
		registry.BiometricSalt,
		registry.CreatedTime,
		registry.PublicKey,
	)
	hash := sha256.Sum256([]byte(hashData))

	// ✅ Step 2: Store Hash in Base58
	publicKey := privateKey.PublicKey
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	// Pad to 32 bytes (secp256k1 coordinates are 32 bytes each)
	paddedX := make([]byte, 32)
	paddedY := make([]byte, 32)
	copy(paddedX[32-len(xBytes):], xBytes)
	copy(paddedY[32-len(yBytes):], yBytes)

	// Concatenate with 0x04 prefix (uncompressed format)
	publicKeyBytes := append([]byte{0x04}, append(paddedX, paddedY...)...)

	// Encode as hex for transmission
	reqToServer.PublicKey = hex.EncodeToString(publicKeyBytes)
	reqToServer.Registration = FinalRegistration{
		DIDHASH:     base58.Encode(hash[:]),
		CreatedTime: time.Now().UTC().Format(time.RFC3339),
		PublicKey:   hex.EncodeToString(publicKeyBytes), // Use hex here
	}

	// ✅ Step 3: Sign the Hash (original bytes, not Base58 encoded string)
	didHashByte := hash[:] // Directly use the hash bytes
	signatureFinal, err := crypto.Sign(didHashByte, privateKey)
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("failed to sign data: %w", err)
	}
	// ✅ Step 4: Encode Signature in Base58
	reqToServer.Signature = base58.Encode(signatureFinal)

	// ✅ Step 5: Marshal to JSON
	jsonData, _ := json.Marshal(reqToServer)
	fmt.Println("Sending JSON:", string(jsonData))

	// ✅ Step 6: Read TLS Certificate
	caCert, err := os.ReadFile("/Users/swanhtet1aungphyo/IdeaProjects/KYC_DID_AUTHENTICATION_SYSTEM/client/internal/cryptography/server.crt")
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("failed to read server certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return &ServerResponse{}, fmt.Errorf("failed to add server certificate to trust pool")
	}

	client := &fasthttp.Client{
		MaxConnsPerHost: 100,
		TLSConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	serverReqBytes, err := json.Marshal(reqToServer)
	if err != nil {
		return &ServerResponse{}, fmt.Errorf("json marshaling failed: %w", err)
	}

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/json")
	req.SetBody(serverReqBytes)

	if err := client.Do(req, resp); err != nil {
		return &ServerResponse{}, fmt.Errorf("failed to send to server: %w", err)
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		log.Println(resp.StatusCode())
		log.Println(string(resp.Body()))
		return &ServerResponse{}, fmt.Errorf("failed to send to server: status code %d", resp.StatusCode())
	}

	respBody := resp.Body()
	log.Println("Raw server response:", string(respBody))
	var serverResponse ServerResponse
	if err := json.Unmarshal(respBody, &serverResponse); err != nil {
		return nil, fmt.Errorf("json unmarshaling failed: %w", err)
	}

	log.Println(respBody)
	log.Printf("Parsed DID: %s", serverResp.DID)
	return &serverResponse, nil
}

func hashBiometric(biometric string, salt []byte) ([]byte, error) {
	hash, err := scrypt.Key([]byte(biometric), salt, biometricN, biometricr, biometricp, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt failed: %w", err)
	}
	return hash, nil
}

func GenerateServerChallenge(did string, clientIP string) (string, error) {
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return "", fmt.Errorf("random generation failed: %w", err)
	}

	record := ChallengeRecord{
		Value:     challenge,
		DID:       did,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		ClientIP:  clientIP,
	}

	key := base58.Encode(challenge)

	challengeStore.Lock()
	challengeStore.store[key] = record
	challengeStore.Unlock()

	return key, nil
}

func ValidateChallenge(challengeKey string, did string, clientIP string) bool {
	challengeStore.RLock()
	record, exists := challengeStore.store[challengeKey]
	challengeStore.RUnlock()

	if !exists || time.Now().After(record.ExpiresAt) {
		return false
	}

	if record.DID != did || record.ClientIP != clientIP {
		return false
	}

	challengeStore.Lock()
	defer challengeStore.Unlock()
	record.UsageCount++
	if record.UsageCount > 1 {
		delete(challengeStore.store, challengeKey)
		return false
	}
	challengeStore.store[challengeKey] = record
	return true
}

func GenerateAuthenticationRequest(account UserAccountLocal, did string, challenge string) (*DIDAuthentication, error) {
	challengeBytes, err := base58.Decode(challenge)
	if err != nil {
		return nil, fmt.Errorf("challenge decoding failed: %w", err)
	}

	signature, err := generateSignature(account.PrivateKey, challengeBytes)
	if err != nil {
		return nil, fmt.Errorf("signature generation failed: %w", err)
	}

	pubKeyBase58 := base58.Encode(account.PublicKey)

	return &DIDAuthentication{
		DID:       did,
		Challenge: challenge,
		Signature: signature,
		PublicKey: pubKeyBase58,
		Timestamp: time.Now().Unix(),
	}, nil
}

func generateSignature(privateKey *ecdsa.PrivateKey, challenge []byte) (ECDSASignature, error) {
	sig, err := secp256k1.Sign(challenge, crypto.FromECDSA(privateKey))
	if err != nil {
		return ECDSASignature{}, fmt.Errorf("signing failed: %w", err)
	}

	return ECDSASignature{
		R: sig[:32],
		S: sig[32:64],
	}, nil
}

func verifySignature(publicKey, challenge, r, s []byte) bool {
	if len(r) != 32 || len(s) != 32 {
		return false
	}

	signature := append(r, s...)
	return secp256k1.VerifySignature(publicKey, challenge, signature)
}

func validatePublicKey(publicKey []byte) bool {
	_, err := crypto.UnmarshalPubkey(publicKey)
	return err == nil
}

func VerifyAuthentication(auth *DIDAuthentication, clientIP string) bool {
	if !ValidateChallenge(auth.Challenge, auth.DID, clientIP) {
		return false
	}

	if time.Now().Unix()-auth.Timestamp > 300 {
		return false
	}

	pubKey, err := base58.Decode(auth.PublicKey)
	if err != nil || !validatePublicKey(pubKey) {
		return false
	}

	challenge, err := base58.Decode(auth.Challenge)
	if err != nil {
		return false
	}

	return verifySignature(pubKey, challenge, auth.Signature.R, auth.Signature.S)
}

func ReadImage(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func HashIt(data []byte) string {
	hash := sha256.Sum256(data)
	return base58.Encode(hash[:])
}
