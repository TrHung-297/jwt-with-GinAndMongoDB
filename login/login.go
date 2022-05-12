package login

import (
	"context"
	"encoding/json"
	"fmt"
	"gin-mongo-api/controllers"
	"gin-mongo-api/models"
	"gin-mongo-api/responses"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/go-redis/redis"
	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson"
)

var jwtKey = []byte("hungts_secret_key")

// Create a struct to read the username and password from the request body
type Credentials struct {
	Password string `json:"password,omitempty" validate:"required"`
	Email    string `json:"email,omitempty" validate:"required"`
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type JWT struct {
	Access_token  string `json:"access_token"`
	Refresh_token string `json:"refresh_token"`
}

// Create a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var client *redis.Client

func Init() {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr:     dsn, //redis port
		Password: "",
		DB:       0,
	})
	_, err := client.Ping().Result()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
}

func Login(c *gin.Context) {

	var creds Credentials
	var validate = validator.New()
	var password_inDB string
	var modell []models.User

	// Get the JSON body and decode into credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: err.Error()})
		return
	}

	if validationErr := validate.Struct(&creds); validationErr != nil {
		c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: validationErr.Error()})
		return
	}

	fmt.Printf("hhung résultddddddd: %v\n", creds)

	filter := bson.D{
		{"$and",
			bson.A{
				bson.D{
					{"email", bson.D{{"$eq", creds.Email}}},
				},
			},
		},
	}

	// retrieve all the documents that match the filter
	cursor, error_find := controllers.UserCollection.Find(context.TODO(), filter)
	// check for errors in the finding
	if error_find != nil {
		c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: error_find.Error()})
		return
	}

	// convert the cursor result to bson
	var results []bson.M
	// check for errors in the conversion
	if error_find = cursor.All(context.TODO(), &results); error_find != nil {
		c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: error_find.Error()})
		return
	}

	fmt.Printf("hhung résult: %v\n", results)
	// display the documents retrieved
	fmt.Printf("hhung check len: %v\n", len(results))
	if len(results) == 0 {
		for _, result := range results {
			fmt.Println(result)
		}
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: "Login failed. Email or password wrong"})
		return
	} else {
		j, err := json.Marshal(results)

		if err != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: err.Error()})
			return
		}
		err1 := json.Unmarshal(j, &modell)
		if err1 != nil {
			c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: err1.Error()})
			return
		}
		for i := range modell {
			fmt.Printf("hungtsssss check password: %v\n", modell[i].Password)
			password_inDB = modell[i].Password
		}
		if password_inDB == creds.Password {
			token_data, err := CreateToken(creds.Email)
			if err != nil {
				c.JSON(http.StatusUnprocessableEntity, responses.UserResponse{Status: http.StatusUnprocessableEntity, Message: "error", Data: err.Error()})
				return
			}
			saveErr := CreateAuth(creds.Email, token_data)
			if saveErr != nil {
				c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
			}
			fmt.Printf("check access uuid:%v\n", token_data.AccessUuid)
			data := &JWT{
				Access_token:  token_data.AccessToken,
				Refresh_token: token_data.RefreshToken,
			}
			c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: data})
			return
		} else {
			c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: "Login failed. Email or password wrong"})
			return
		}
	}
	// cookie := new(gin.cookies)
	// cookie.Name = "token"
	// cookie.Value = tokenString
	// cookie.Expires = expirationTime
	// // Set cookie
	// c.Cookie(cookie)

	// return c.Status(http.StatusFound).JSON(responses.UserResponse{Status: http.StatusFound, Message: "error", Data: &fiber.Map{"data": data}})
}

func CreateToken(email string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = email
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = email
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
	// We can use code below
	/*
		expirationTime := time.Now().Add(5 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &Claims{
			Username: "hungts",
			StandardClaims: jwt.StandardClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: expirationTime.Unix(),
			},
		}

		// Declare the token with the algorithm used for signing, and the claims
		token_ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string
		tokenString, err := token_.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: {"data": err.Error()}})
		}
	*/
}

func CreateAuth(userid string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUuid, userid, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(td.RefreshUuid, userid, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, responses.UserResponse{Status: http.StatusUnprocessableEntity, Message: "error", Data: err.Error()})
		return
	}
	refreshToken := mapToken["refresh_token"]

	//verify the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: "Refresh token expired"})
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: err.Error()})
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok1 := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok1 {
			c.JSON(http.StatusUnprocessableEntity, responses.UserResponse{Status: http.StatusUnprocessableEntity, Message: "error", Data: err.Error()})
			return
		}
		_email, ok2 := claims["user_id"].(string) //convert the interface to string
		if !ok2 {
			c.JSON(http.StatusUnprocessableEntity, responses.UserResponse{Status: http.StatusUnprocessableEntity, Message: "error", Data: "Error occurred"})
			return
		}
		//Delete the previous Refresh Token
		deleted, delErr := DeleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 { //if any goes wrong
			c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: "unauthorized"})
			return
		}
		//Create new pairs of refresh and access tokens
		ts, createErr := CreateToken(_email)
		if createErr != nil {
			c.JSON(http.StatusForbidden, responses.UserResponse{Status: http.StatusForbidden, Message: "error", Data: createErr.Error()})
			return
		}
		//save the tokens metadata to redis
		saveErr := CreateAuth(_email, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, responses.UserResponse{Status: http.StatusForbidden, Message: "error", Data: saveErr.Error()})
			return
		}
		data := &JWT{
			Access_token:  ts.AccessToken,
			Refresh_token: ts.RefreshToken,
		}
		c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: data})
		return
	} else {
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "success", Data: "refresh expired"})
		return
	}
}
