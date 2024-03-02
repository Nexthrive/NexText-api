package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Login struct {
	ID         primitive.ObjectID   `bson:"_id" json:"id,omitempty"`
	Email      string               `bson:"email" json:"email"`
	Passphrase string               `bson:"passphrase" json:"passphrase"`
	
}
