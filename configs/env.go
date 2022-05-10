package configs

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func EnvMongoURI() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("MONGOURI")
}

func Env_SecretKey() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	fmt.Printf("check enviroment key1: %v , key2: %v\n", os.Getenv("ACCESS_SECRET"), os.Getenv("REFRESH_SECRET"))
	os.Setenv("ACCESS_SECRET", os.Getenv("ACCESS_SECRET"))
	os.Setenv("REFRESH_SECRET", os.Getenv("REFRESH_SECRET"))

}
