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

var (
	mutex   sync.Mutex
	clients = make(map[string]*websocket.Conn)
)

type WebsocketMessage struct {
	Text string `json:"text"`
}

var encryptkey = []byte(os.Getenv("ENCRYPT_KEY"))

func GetMessages(sender string, receiver string) ([]models.Message, error) {
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

func broadcastMessage(message models.Message) {
	mutex.Lock()
	defer mutex.Unlock()

	for _, conn := range clients {
			// Exclude sender from receiving their own messages
			if message.Sender != conn.RemoteAddr().String() {
					err := conn.WriteJSON(message)
					if err != nil {
							fmt.Println("error broadcasting message:", err)
					}
			}
	}
}

func HandleWebSocket(c *gin.Context) {
	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Println("error upgrading to WebSocket:", err)
		return
	}

	sender := c.Param("UserID")
	receiver := c.Param("ReceiverID")

	mutex.Lock()
	_, online := clients[receiver]
	mutex.Unlock()

	if online {
		fmt.Printf("User %s is online\n", receiver)
	} else {
		storedMessages, err := GetMessages(sender, receiver)
		if err != nil {
			fmt.Println("Error retrieving stored messages:", err)
		} else {
			for _, msg := range storedMessages {
				decryptedText, err := decrypt(msg.Text, encryptkey)
				if err != nil {
					fmt.Println("Error decrypting message:", err)
					continue
				}

				decryptedMessage := models.Message{
					Timestamp: msg.Timestamp,
					Text:      decryptedText,
					Sender:    msg.Sender,
					Receiver:  msg.Receiver,
				}

				conn.WriteJSON(decryptedMessage)
			}
		}
	}

	mutex.Lock()
	clients[sender] = conn
	mutex.Unlock()

	defer func() {
		mutex.Lock()
		delete(clients, sender)
		mutex.Unlock()
		conn.Close()
	}()

	for {
		var wsMsg WebsocketMessage

		err := conn.ReadJSON(&wsMsg)
		if err != nil {
			fmt.Println("error reading WebSocket message:", err)
			break
		}

		message := models.Message{
			Timestamp: time.Now(),
			Text:      wsMsg.Text,
			Sender:    sender,
			Receiver:  receiver,
		}

		err = SaveMessage(message)
		if err != nil {
			fmt.Println("error saving message:", err)
		}

		broadcastMessage(message)
	}
}

// encrypt function takes plaintext and a key, and returns the base64-encoded ciphertext
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

// decrypt function takes base64-encoded ciphertext and a key, and returns the plaintext
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
