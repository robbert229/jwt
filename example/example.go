package main
import (
    "github.com/robbert229/jwt"   
    "fmt" 
)

func main() {
    secret := "ThisIsMySuperSecret"
    algorithm := jwt.HmacSha256(secret)
    
    claims := jwt.NewClaim()
    claims["isAdmin"] = true
    
    token, err := jwt.Encode(algorithm, claims)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Token: %s\n", token)
    
    if jwt.Verify(algorithm, token) != nil {
        panic(err)
    }
}