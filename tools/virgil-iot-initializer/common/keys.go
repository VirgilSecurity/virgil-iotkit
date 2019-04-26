package common


type VirgilPrivateKeyInterface interface {
	IsPrivate() bool
	Identifier() []byte
}

type VirgilPublicKeyInterface interface {
	IsPublic() bool
	Identifier() []byte
}
