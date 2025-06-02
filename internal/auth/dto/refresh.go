package dto

type RefreshInput struct {
	RefreshToken string `json:"refresh_token"`
	Fingerprint  string `json:"-"`
	IPAddress    string `json:"-"`
	UserAgent    string `json:"-"`
}
