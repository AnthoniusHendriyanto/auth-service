package dto

type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
