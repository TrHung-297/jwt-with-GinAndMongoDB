package routes

import (
	"gin-mongo-api/controllers"
	"gin-mongo-api/login"
	"gin-mongo-api/todo"

	"github.com/gin-gonic/gin"
)

func UserRoute(router *gin.Engine) {

	//All routes related to users comes here
	router.POST("/user", controllers.CreateUser)
	router.GET("/user/:userId", controllers.GetAUser)
	router.PUT("/user/:userId", controllers.EditAUser)
	router.DELETE("/user/:userId", controllers.DeleteAUser)
	router.GET("/users", controllers.GetAllUsers)
	router.POST("/login", login.Login)
	router.POST("/logout", login.Logout)
	router.POST("/todo", todo.CreateTodo)
}
