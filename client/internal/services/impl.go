package services

import (
	"errors"
	"github.com/SwanHtetAungPhyo/kycdid/internal/cryptography"
	"github.com/SwanHtetAungPhyo/kycdid/internal/model"

	"github.com/goccy/go-json"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/bcrypt"
)

type ServicesImpl struct {
}

func NewServicesImpl() *ServicesImpl {
	return &ServicesImpl{}
}

func (s ServicesImpl) GenerateWalletService(password string) (string, error) {
	account := cryptography.KeyGeneration()

	filePath, err := cryptography.SaveToLocalWithPassword(account, password)
	if err != nil {
		return "", err
	}

	return filePath, nil
}
func (s ServicesImpl) GetAccountService(password string) (interface{}, error) {
	withPassword, err := cryptography.LoadFromLocalWithPassword(password)
	if err != nil {
		return "", err
	}

	return withPassword, nil
}

func (s *ServicesImpl) StoreInKeyChain(req model.RequestBody) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	toSaved := model.RequestBody{
		FullName: req.FullName,
		Email:    req.Email,
		Password: string(hashedPassword),
	}
	jsonData, err := json.Marshal(toSaved)
	if err != nil {
		return err
	}

	err = keyring.Set(model.ServiceName, req.Email, string(jsonData))
	if err != nil {
		return err
	}

	return nil
}

func (s ServicesImpl) AuthenticationFromKeyChain(username, password string) (bool, error) {
	hashedPassword, err := keyring.Get(model.ServiceName, username)
	var req model.RequestBody
	err = json.Unmarshal([]byte(hashedPassword), &req)
	if err != nil {
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(req.Password), []byte(password)); err != nil {
		return false, errors.New("invalid credentials")
	}

	return true, nil
}
