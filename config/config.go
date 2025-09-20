package config

import (
	"log"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Config struct {
		Mode  string
		Key   string
		Type  string
		Ports []string
	}
}

func LoadConfig() (config *Config) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		log.Fatal("CONFIG_PATH is not set")
	}
	viper.SetConfigFile(configPath)
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
	if err := viper.Unmarshal(&config); err != nil {
		panic("ERROR load config file!")
	}
	log.Println("================ Loaded Configuration ================")
	return
}
