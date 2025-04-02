package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type Config struct {
	ServerAddr string `mapstructure:"server_addr"`
	ServerPort int    `mapstructure:"server_port"`
	LogLevel   string `mapstructure:"log_level"`
	DBHost     string `mapstructure:"db_host"`
	DBPort     int    `mapstructure:"db_port"`
	DBUser     string `mapstructure:"db_user"`
	DBPassword string `mapstructure:"db_password"`
	DBName     string `mapstructure:"db_name"`
}

func LoadConfig(path string) (*Config, error) {
	// Set the file name of the configurations file
	viper.SetConfigName("config")
	// Set the configurations file type (YAML, JSON, TOML, etc.)
	viper.SetConfigType("yaml")
	// Set the path to look for the configurations file
	viper.AddConfigPath(path)

	// Set default values for production readiness.
	viper.SetDefault("server_addr", "0.0.0.0")
	viper.SetDefault("server_port", 8080)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("db_host", "localhost")
	viper.SetDefault("db_port", 5432)
	viper.SetDefault("db_user", "postgres")
	viper.SetDefault("db_password", "password")
	viper.SetDefault("db_name", "app_db")

	if err := viper.ReadInConfig(); err != nil {

		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	viper.AutomaticEnv()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode into config struct: %w", err)
	}

	return &config, nil
}
