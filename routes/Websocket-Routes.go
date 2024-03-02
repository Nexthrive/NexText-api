package routes

import (
	"github.com/Nexthrive/NexText/handlers"
	"github.com/gin-gonic/gin"
)

func WebSocketRoutes (r *gin.Engine) {
	r.GET("/ws/:UserID/:ReceiverID", handlers.HandleWebSocket)
}