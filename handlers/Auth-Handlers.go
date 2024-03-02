package handlers

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/Nexthrive/NexText/auth"
	"github.com/Nexthrive/NexText/db"
	"github.com/Nexthrive/NexText/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var collection = db.GetMongoDBClient().Database("Nex").Collection("users")
var collectionFriendReq = db.GetMongoDBClient().Database("Nex").Collection("friend_req")

func CreateUser(c *gin.Context) {
	// body
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Passphrase), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	user.Passphrase = string(hashedPassword)
	user.Status = false
	user.ID = primitive.NewObjectID()

	// checking if there is any user based on email
	var existingUser models.User
	err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == mongo.ErrNoDocuments {
		// generate otp
		otp := rand.Intn(999999-100000) + 100000

		// body of the mail
		m := gomail.NewMessage()
		m.SetHeader("From", "nexthrivestudios@gmail.com")
		m.SetHeader("To", user.Email)
		m.SetHeader("Subject", "NexText OTP")

		logoPath := "../assets/NexText.png"

		// HTML body with styling
		htmlBody := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<style>
				body {
					font-family: Arial, sans-serif;
					background-color: #fff; /* Secondary color */
					color: #000; /* Primary color */
					margin: 0;
					padding: 0;
				}
				.container {
					max-width: 600px;
					margin: 0 auto;
					padding: 20px;
				}
				.header {
					background-color: #000; /* Primary color */
					color: #fff; /* Secondary color */
					text-align: center;
					padding: 10px;
				}
				.logo img {
					max-width: 100px;
					height: auto;
				}
				.content {
					background-color: #fff; /* Secondary color */
					padding: 20px;
					border-radius: 5px;
					box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
				}
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<div class="logo">
						<img src="%s" alt="Logo">
					</div>
					<h1>NexText OTP</h1>
				</div>
				<div class="content">
					<p>Your OTP is: <strong>%d</strong></p>
				</div>
			</div>
		</body>
		</html>
	`, logoPath, otp)

		m.SetBody("text/html", htmlBody)
		d := gomail.NewDialer("smtp.gmail.com", 587, "nexthrivestudios@gmail.com", "vnujtsexvthxuykv")

		// send mail
		if err := d.DialAndSend(m); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.OTP = otp

		_, insert := collection.InsertOne(context.TODO(), user)
		if insert != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": insert.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "user created succes",
			"user":    user,
		})
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	} else if err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot find user"})
		return
	}

	// checking if the name is unique
	err = collection.FindOne(context.TODO(), bson.M{"name": user.Name}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name is already taken"})
		return
	} else if err != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// generate OTP
	otp := rand.Intn(999999-100000) + 100000

	// body of the mail
	m := gomail.NewMessage()
	m.SetHeader("From", "idklol0209@gmail.com")
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "NexText OTP")
	m.SetBody("text/plain", fmt.Sprintf("Your OTP is: %d", otp))

	d := gomail.NewDialer("smtp.gmail.com", 587, "nexthrivestudios@gmail.com", "vnujtsexvthxuykv")

	// send mail
	if err := d.DialAndSend(m); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user.OTP = otp

	_, insert := collection.InsertOne(context.TODO(), user)
	if insert != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": insert.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
		"user":    user,
	})
}

func VerifyOTP(c *gin.Context) {
	// request
	var req models.VerifyOTP
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	//get data user by email

	var user models.User
	if err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&user); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}
	//compare otp
	if req.Otp != user.OTP {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}

	//update status user if otp is right
	get := bson.M{"email": req.Email}
	query := bson.M{"$set": bson.M{"status": true}}

	if _, err := collection.UpdateOne(context.TODO(), get, query); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	//create token based on aut/generate-token
	token, err := auth.CreateToken(user.Email, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	//response
	c.JSON(http.StatusOK, gin.H{
		"message": "OTP verified successfully",
		"token":   token,
	})
}

func Login(c *gin.Context) {
	var req models.Login

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//get data user by email
	var user models.User
	if err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&user); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email"})
		return
	}

	//compare password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Passphrase), []byte(req.Passphrase)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	//create token based on auth/generate-token
	token, err := auth.CreateToken(user.Email, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	//response
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successfully",
		"token":   token,
	})
}
func GetUserById(c *gin.Context) {
	// Get token from request
	tokenString := c.GetHeader("Authorization")

	// Check if token is missing
	if tokenString == "" {
		fmt.Println("Token missing")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	fmt.Println("{token:}", tokenString)

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("gabolehdiliatbangrahasiainikaloluliatberartiluhmengakuigwganteng"), nil
	})

	// Check if there's an error during token parsing
	if err != nil {
		fmt.Println("Token parsing error:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token: " + err.Error()})
		return
	}

	// Check if token is invalid
	if !token.Valid {
		fmt.Println("Invalid token")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token: signature is invalid"})
		return
	}
	// Extract user ID from token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Failed to extract claims from token")
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to extract claims from token"})
		return
	}

	userID, ok := claims["id"].(string)
	if !ok {
		fmt.Println("Failed to extract user ID from token claims")
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to extract user ID from token claims"})
		return
	}

	// Convert the userID string to primitive.ObjectID
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		fmt.Println("Error converting user ID to ObjectID:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to convert user ID to ObjectID"})
		return
	}

	var user models.User
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}
