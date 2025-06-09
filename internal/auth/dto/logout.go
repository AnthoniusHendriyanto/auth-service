package dto

type LogoutInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}
