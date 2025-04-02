package utils

func FailOnErrorWithPanic(err error, msg string) {
	if err != nil {
		panic(msg + ": " + err.Error())
	}
}

func RecoverFromPanic() {
	if r := recover(); r != nil {
		logger.Printf("Recovered from panic: %v", r)
	}
}

func LogError(err error, msg string) {
	if err != nil {
		logger.WithError(err).Error(msg)
	}
}

func Warn(err error) {
	if err != nil {
		logger.WithError(err).Warn(err.Error())
	}
}
