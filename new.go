package main

//
//import (
//	"fmt"
//	"github.com/SwanHtetAungPhyo/nigga/internal/cryptography"
//	"github.com/goccy/go-json"
//	"log"
//)
//
//func main() {
//	password := "SecurePassword123!"
//
//	data, err := cryptography.ReadImage("/Users/swanhtet1aungphyo/IdeaProjects/Nigga/img.png")
//
//	failOnError(err, "failed to read image")
//	biometricHash := cryptography.HashIt(data)
//
//	biometric := fmt.Sprintf("%x", biometricHash)
//
//	account := cryptography.KeyGeneration()
//
//	_, err = cryptography.SaveToLocalWithPassword(account, password)
//	if err != nil {
//		log.Fatal("Account storage failed:", err)
//	}
//
//	loadedAccount, err := cryptography.LoadFromLocalWithPassword(password)
//	failOnError(err, "Account load failed")
//
//	did, registry, err := cryptography.CreateDID(loadedAccount, biometric, "NNFNFNFNNFs")
//	failOnError(err, "DID creation failed")
//
//	fmt.Printf("DID=%s\n", did)
//	prettyJson, err := json.MarshalIndent(registry, "", "  ")
//	failOnError(err, "JSON marshal failed")
//	fmt.Println(string(prettyJson))
//	serverChallenge, err := cryptography.GenerateServerChallenge(did, "127.0.0.1")
//	failOnError(err, "Server challenge failed")
//
//	authReq, err := cryptography.GenerateAuthenticationRequest(loadedAccount, did, serverChallenge)
//	failOnError(err, "Auth request failed")
//
//	if cryptography.VerifyAuthentication(authReq, "127.0.0.1") {
//		fmt.Println("Authentication successful")
//	} else {
//		fmt.Println("Authentication failed")
//	}
//	didUnchain := cryptography.OnChain{
//		Did: did,
//	}
//	cryptography.AddToOnChain(didUnchain)
//
//	fmt.Printf("%x\n", biometricHash)
//
//	prettyJSON2, err := json.MarshalIndent(cryptography.GetOnChainData(did), "", "  ")
//	failOnError(err, "JSON marshal failed")
//	fmt.Println(string(prettyJSON2))
//	fmt.Println(cryptography.GetOnChainData(did))
//}
//
//func failOnError(err error, msg string) {
//	if err != nil {
//		log.Fatal(msg, err)
//	}
//}
