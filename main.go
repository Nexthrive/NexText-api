package main

import (
	"context"
	"log"
	"net/http"

	"github.com/Nexthrive/NexText/db"
	"github.com/Nexthrive/NexText/routes"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Get MongoDB client instance
	client := db.GetMongoDBClient()

	// Check the connection
	err := client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	r := gin.Default()

	// Use CORS middleware with specific configuration
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true // Allow all origins, you can also set a specific origin
	config.AllowHeaders = append(config.AllowHeaders, "Authorization")
	r.Use(cors.New(config))

	routes.UserRoutes(r)
	routes.WebSocketRoutes(r)
	routes.FriendRoutes(r)

	r.Handle(http.MethodGet, "/", Handler)
	
	r.Run(":8080")
}


func Handler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hello from the handler!",
	})
}