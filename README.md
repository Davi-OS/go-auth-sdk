# go-auth-sdk

SDK em Go para serviços que aceitam os access tokens do
[go-auth-service](https://github.com/Davi-OS/go-auth-service). A validação é
local: assinatura ES256, `iss`, `exp` e `aud` são conferidos com a chave
pública do JWKS, e a revogação chega por polling leve (`GET /revocations`),
sem uma chamada ao auth a cada request.

```sh
go get github.com/Davi-OS/go-auth-sdk@latest
```

```go
client, err := authsdk.New(ctx, authsdk.Config{
	BaseURL:  "https://auth.exemplo.com", // URL do auth
	Audience: "meu-sistema",              // slug do sistema cadastrado no auth
	Issuer:   "https://auth.exemplo.com", // AUTH_ISSUER do auth
})
if err != nil {
	log.Fatal(err) // o JWKS é buscado no boot: o auth precisa estar no ar
}
defer client.Close()

mux.Handle("GET /faturas", client.RequirePermission("fatura:read")(listarFaturas))

func listarFaturas(w http.ResponseWriter, r *http.Request) {
	claims, _ := authsdk.ClaimsFromContext(r.Context())
	// claims.Subject = usuário, claims.OrgID = organização (tenant)
}
```

## Pacotes

- `authsdk`: cliente com cache de revogação (`New`, `Verify`, `Close`) e
  middlewares `net/http` (`Authenticate`, `RequirePermission`, `RequireRole`).
- `token`: o contrato do token, compartilhado com o auth: `Claims`, formato
  JWKS e o verificador ES256. A assinatura fica só no auth.

Não há segredos aqui: os consumidores só têm a chave pública.
