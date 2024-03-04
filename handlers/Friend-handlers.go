package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Nexthrive/NexText/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// AddFriend handler

func AddFriend(c *gin.Context) {
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

	// request
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// var req models.UserReq
	var friendReq models.FriendReq

	// Attempt to find the user by email
	err = collection.FindOne(context.TODO(), bson.M{"name": user.Name}).Decode(&user)
	if err != nil {
		// Check if the error is due to user not found
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Otherwise, return a generic error message
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error: " + err.Error()})
		return
	}
	fmt.Println(user)

	friendReq.FromID = objectID
	friendReq.ToID = user.ID
	friendReq.Status = "pending"

	_, insertErr := collectionFriendReq.InsertOne(context.TODO(), friendReq)
	if insertErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": insertErr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Friend request sent"})
}

func GetFriendReq(c *gin.Context) {
	//request
	var req models.FriendReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
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

	// get friend request
	err = collectionFriendReq.FindOne(context.TODO(), bson.M{"ToID": objectID}).Decode(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusNotFound, gin.H{"error": "No friend request found"})
		return
	}
	var user models.User
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err == mongo.ErrNoDocuments {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": req.ToID,
		"name": user.Name,
	})
}

func GetFriends(c *gin.Context) {
	// Get token from request
	tokenString := c.GetHeader("Authorization")

	// Check if token is missing
	if tokenString == "" {
		fmt.Println("Token missing")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}

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

	// Find the user by ID to get their friends
	var user models.User
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Extract and format friends data
	var friendsData []gin.H
	for _, friendID := range user.Friends {
		var friend models.User
		err := collection.FindOne(context.TODO(), bson.M{"_id": friendID}).Decode(&friend)
		if err == nil {
			friendData := gin.H{
				"id":   friend.ID,
				"name": friend.Name,
			}
			friendsData = append(friendsData, friendData)
		}
	}

	c.JSON(http.StatusOK, gin.H{"friends": friendsData})
}

func DeclineFriend(c *gin.Context) {
	var req models.FriendReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := collectionFriendReq.FindOneAndUpdate(context.TODO(), bson.M{"_id": req.ID}, bson.M{"$set": bson.M{"status": "declined"}}).Decode(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Friend request declined"})
}

func AccFriend(c *gin.Context) {
	var req models.FriendReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := collectionFriendReq.FindOneAndUpdate(context.TODO(), bson.M{"ToID": req.ToID}, bson.M{"$set": bson.M{"status": "accepted"}}).Decode(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	if err := collection.FindOneAndUpdate(context.TODO(), bson.M{"_id": req.FromID}, bson.M{"$push": bson.M{"friends": req.ToID}}).Decode(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	if err := collection.FindOneAndUpdate(context.TODO(), bson.M{"_id": req.ToID}, bson.M{"$push": bson.M{"friends": req.FromID}}).Decode(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Friend request accepted"})
}
