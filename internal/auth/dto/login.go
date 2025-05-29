package dto

type LoginInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Fingerprint string `json:"-"`
	IPAddress   string `json:"-"`
	UserAgent   string `json:"-"`
}
