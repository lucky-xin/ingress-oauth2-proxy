package samples

type XyzUser struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type XyzOAuth2Token struct {
	AccessToken  string `json:"access_token" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
	TokenType    string `json:"token_type" binding:"required"`
	ExpiresIn    int64  `json:"expires_in" binding:"required"`
	Username     string `json:"username" binding:"required"`
	TenantId     int64  `json:"tenant_id" binding:"required"`
}
