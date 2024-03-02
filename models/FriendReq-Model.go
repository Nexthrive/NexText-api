package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type FriendReq struct {
	ID     primitive.ObjectID `bson:"_id,omitempty"`
	FromID primitive.ObjectID `bson:"FromID,omitempty"`
	ToID   primitive.ObjectID `bson:"ToID,omitempty"`
	Status string
}
