package main

import (
	"gin-mongo-api/configs"
	"gin-mongo-api/login"
	"gin-mongo-api/routes"

	//add this
	"github.com/gin-gonic/gin"
)

func main() {
	configs.Env_SecretKey()
	login.Init()
	router := gin.Default()
	//run database
	configs.ConnectDB()
	routes.UserRoute(router)

	router.Run(":8080")

}
