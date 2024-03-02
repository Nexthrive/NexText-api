package routes

import (
	"github.com/Nexthrive/NexText/handlers"
	"github.com/gin-gonic/gin"
)

func UserRoutes(r *gin.Engine) {
	r.POST("/signup", handlers.CreateUser)
	r.POST("/verify-otp", handlers.VerifyOTP)
	r.POST("/login", handlers.Login)
	r.GET("/user", handlers.GetUserById)
}
