package main
import (
    "github.com/robbert229/jwt"   
    "fmt" 
	"time"
)

func main() {
    secret := "ThisIsMySuperSecret"
    algorithm := jwt.HmacSha256(secret)
    
    claims := jwt.NewClaim()
    claims["isAdmin"] = true
    claims["exp"] = int(time.Now().Unix()) + 60


    token, err := jwt.Encode(algorithm, claims)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Token: %s\n", token)
    
    if jwt.Verify(algorithm, token) != nil {
        panic(err)
    }
    
    loadedClaims, err := jwt.LoadClaims(algorithm, token)
    if err != nil {
        panic(err)
    }
    
    if loadedClaims["isAdmin"].(bool) == true {
        //user is an admin    
        fmt.Println("User is an admin")
    }
}