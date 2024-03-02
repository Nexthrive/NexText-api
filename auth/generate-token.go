package auth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func CreateToken(email string, id primitive.ObjectID) (string, error) {
	// Create new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Define the claims to be added to the token
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["id"] = id.Hex() // Convert ObjectID to string
	claims["exp"] = jwt.TimeFunc().Add(time.Hour * 72).Unix()

	// Generate the token string using the secret key
	secretKey := []byte("gabolehdiliatbangrahasiainikaloluliatberartiluhmengakuigwganteng")
	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}
	return tokenString, nil
}
