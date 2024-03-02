package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID         primitive.ObjectID   `bson:"_id" json:"id,omitempty"`
	Name       string               `bson:"name" json:"name"`
	Email      string               `bson:"email" json:"email"`
	Passphrase string               `bson:"passphrase" json:"passphrase"`
	Friends    []primitive.ObjectID `bson:"friends,omitempty"`
	OTP        int                  `bson:"otp" json:"otp"`
	Status     bool                 `bson:"status" json:"status"`
}
