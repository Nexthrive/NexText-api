package db

import (
	"context"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func init() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Println(err)
	}

	// Set MongoDB connection URI from environment variable
	uri := os.Getenv("MONGODB_URL")
	if uri == "" {
		panic("MONGODB_URL is not set in the environment variables")
	}

	// Set up MongoDB client options
	clientOptions := options.Client().ApplyURI(uri)

	// Connect to MongoDB
	var err error
	client, err = mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		panic(err)
	}

	// Check the connection
	err = client.Ping(context.Background(), nil)
	if err != nil {
		panic(err)
	}


	fmt.Println("Connected to MongoDB!")
}

// GetMongoDBClient returns the MongoDB client instance
func GetMongoDBClient() *mongo.Client {
	return client
}

