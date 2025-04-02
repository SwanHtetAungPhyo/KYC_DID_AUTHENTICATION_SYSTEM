package services

type Services interface {
	GenerateWalletService(password string) (string, error)
}
