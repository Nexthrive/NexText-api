package models

import "time"

type Message struct {
	ID         string
	Timestamp  time.Time
	Text       string
	Sender     string
	Receiver    string
}