package utils

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"path"
	"runtime"
	"time"
)

var logger *logrus.Logger

func Init() {
	logger = logrus.New()
	logger.SetReportCaller(true) // Enable caller reporting

	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339, // Use a standard timestamp format
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
			logrus.FieldKeyFile:  "caller",
		},
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
		},
		PrettyPrint: true,
	})
}

func GetLogger() *logrus.Logger {
	return logger
}
