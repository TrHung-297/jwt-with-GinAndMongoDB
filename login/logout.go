package login

import (
	"fmt"
	"gin-mongo-api/responses"
	"gin-mongo-api/todo"
	"net/http"

	"github.com/gin-gonic/gin"
)

func DeleteAuth(givenUuid string) (int64, error) {
	fmt.Printf("uuid: %v\n", givenUuid)
	deleted, err := client.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func Logout(c *gin.Context) {
	au, err := todo.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: "unauthorized 1"})
		return
	}
	deleted, delErr := DeleteAuth(au.AccessUuid)
	if delErr != nil || deleted == 0 { //if any goes wrong
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: "unauthorized 2"})
		return
	}
	c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "error", Data: "Successfully logged out"})
	return
}
