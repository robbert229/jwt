[![Build Status](https://travis-ci.org/robbert229/jwt.svg?branch=master)](https://travis-ci.org/robbert229/jwt) [![codecov](https://codecov.io/gh/robbert229/jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/robbert229/jwt)

# jwt
This is a minimal implementation of JWT designed with simplicity in mind.

#What is JWT?
Jwt is a signed JSON object used for claims based authentication. A good resource on what JWT Tokens are is [jwt.io](https://jwt.io/), and in addition you can always read the [RFC](https://tools.ietf.org/html/rfc7519).

This implementation doesn't fully follow the specs in that it ignores the algorithm claim on the header. It does this due to the security vulnerability in the JWT specs. Details on the vulnerability can be found [here](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)

##What algorithms does it support?
* HS256
* HS384
* HS512

##How does it work?

###How to create a token?
Creating a token is actually pretty easy.

The first step is to pick a signing method. For demonstration purposes we will choose HSMAC256.

    algorithm :=  gwt.HmacSha256("ThisIsTheSecret")
   
Now we need to the claims, and edit some values

    claims := jwt.NewClaim()
    claims["isAdmin"] = true
    
Then we will need to sign it!

    token, err := jwt.Encode(algorithm, claims)
    if err != nil {
        panic(err)    
    }
    
###How to authenticate a token?
Authenticating a token is quite simple. All we need to do is...

    if jwt.Verify(algorithm, token) == nil {
        //authenticated
    } 
    
###How do we get the claims?
The claims are stored in a `map[string]interface{}`. To get the claims from a token simply...
    
    claims, err := jwt.LoadClaims(algorithm, token)
    if err != nil {
        panic(err)
    }
    
    if claims["isAdmin"].(bool) == true {
        //user is an admin    
    }
    
From there on the claims can