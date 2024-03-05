package routes

import (
	"github.com/Nexthrive/NexText/handlers"
	"github.com/gin-gonic/gin"
)

func FriendRoutes(r *gin.Engine) {
	r.POST("/add-friend", handlers.AddFriend)
	r.PUT("/accept", handlers.AcceptFriend)
	r.GET("/friends", handlers.GetFriendReq)
	r.GET("/friends/list", handlers.GetFriends)
}
