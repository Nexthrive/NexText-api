package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Nexthrive/NexText/models"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type WebsocketMessage struct {
	Text       string    `json:"text"`
	ReceiverID string    `json:"receiver_id"`
	Timestamp  time.Time `json:"timestamp"`
}

var (
	mutex        sync.Mutex
	clients      = make(map[string]*websocket.Conn)
	// messageQueue = make(map[string][]models.Message)
)


var encryptkey = []byte(os.Getenv("ENCRYPT_KEY"))

func GetMessages(sender, receiver string) ([]models.Message, error) {
	filter := bson.M{
		"$or": []bson.M{
			{"sender": sender, "receiver": receiver},
			{"sender": receiver, "receiver": sender},
		},
	}

	cursor, err := collectionMessages.Find(context.Background(), filter)
	if err != nil {
		return nil, fmt.Errorf("error finding messages %v", err)
	}
	defer cursor.Close(context.Background())

	var messages []models.Message
	for cursor.Next(context.Background()) {
		var message models.Message
		if err := cursor.Decode(&message); err != nil {
			return nil, fmt.Errorf("error decoding message %v", err)
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func SaveMessage(message models.Message) error {
	key := encryptkey
	encryptedText, err := encrypt(message.Text, key)
	if err != nil {
		return fmt.Errorf("error encrypting message: %v", err)
	}
	_, err = collectionMessages.InsertOne(context.Background(), bson.M{
		"timestamp": message.Timestamp,
		"text":      encryptedText,
		"sender":    message.Sender,
		"receiver":  message.Receiver,
	})
	if err != nil {
		return fmt.Errorf("error inserting message into database: %v", err)
	}
	return nil
}

func encrypt(text string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, key []byte) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}

func HandleWebSocket(c *gin.Context) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

    ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        log.Println("WebSocket Upgrade Error:", err)
        return
    }
    defer ws.Close()

    // Extract user ID and friend ID from headers
    userID := c.Query("UserID")
    friendID := c.Query("FriendID")

    fmt.Println("User ID:", userID)

    if userID == "" || friendID == "" {
        log.Println("Invalid UserID or FriendID in query parameters")
        return
    }

    // Register the WebSocket connection
    mutex.Lock()
    clients[userID] = ws
    mutex.Unlock()

	// Load existing messages from the database
	messages, err := GetMessages(userID, friendID)
	if err != nil {
			log.Println("Error retrieving messages from the database:", err)
			return
	}

	// Send existing messages to the client
	for _, message := range messages {
		decryptedText, err := decrypt(message.Text, encryptkey)
		if err != nil {
			log.Println("Error decrypting message:", err)
			return
		}
	
		ws.WriteJSON(WebsocketMessage{
			Text:       decryptedText,
			ReceiverID: message.Receiver,
			Timestamp:  message.Timestamp,
		})
	}

	// Handle incoming WebSocket messages
	for {
			var wsMessage WebsocketMessage
			err := ws.ReadJSON(&wsMessage)
			if err != nil {
					log.Println("WebSocket Read Error:", err)
					break
			}

			// Save the message to the database
			err = SaveMessage(models.Message{
					Timestamp: time.Now(),
					Text:      wsMessage.Text,
					Sender:    userID,
					Receiver:  friendID,
			})
			if err != nil {
					log.Println("Error saving message to the database:", err)
					break
			}

			// Broadcast the message to the friend if they are online
			mutex.Lock()
			friendWS, ok := clients[friendID]
			mutex.Unlock()

			if ok {
					go func() {
							friendWS.WriteJSON(WebsocketMessage{
									Text:       wsMessage.Text,
									ReceiverID: friendID,
							})
					}()
			}
	}
}




