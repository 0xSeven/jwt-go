# jwt-go

[![Build Status](https://travis-ci.org/dgrijalva/jwt-go.svg?branch=master)](https://travis-ci.org/dgrijalva/jwt-go)
[![GoDoc](https://godoc.org/github.com/dgrijalva/jwt-go?status.svg)](https://godoc.org/github.com/dgrijalva/jwt-go)

A [go](http://www.golang.org) (or 'golang' for search engine friendliness) implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

**NEW VERSION COMING:** 

package Cryptic
```golang
/*
	tokenManager.go
	This file is used to generate and verify a token.
	RFC3339 will be used for time format.
//  ! Has environment variables
 */

 /*
 	Token fields:
 		UserId - int
 		CreationDate - String
  */
import (
	"github.com/dgrijalva/jwt-go"
	"../ErrorLogger"
	"time"
	"strconv"
	"fmt"

)

const HASHING_KEY_01 = "JIzMP7CIyW1T5TgG8ctjv6nNgCvZBiil"
const TOKEN_INVALID_RESPONSE = 403
const MAX_DAYS_VALIDATION = 90

func GenerateNewToken(Id int64) (bool,string) { //Requires userId.


	//Creating new token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Id": strconv.FormatInt(Id, 10), //The Id of the user.
		"CreationDate": time.Now().UTC().Format(time.RFC3339),

	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(HASHING_KEY_01))
	if err != nil {
		ErrorLogger.ReportError(ErrorLogger.ErrorMessage{Error:err, Message:("Unable to generate a token."),  Priority:ErrorLogger.HIGH_PRIORITY, Category: "api"})
		return false, ""
	}

	//Returning tokenString.
	return true, tokenString

}

func IsValid(tokenString string) (bool, bool, string){ //first return type is the success, second is the validation and last one is the UserId.

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(HASHING_KEY_01), nil
	})

	//Checking for errors.
	if err != nil {
		return false, false, ""
	}

	//Getting claims.
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//Token is valid.
		//Getting claims.
		Id := claims["Id"].(string)

		if Id == ""{
			return true, false, ""
		}
		//Checking creationDate
		//Getting current time
		currentTime := time.Now().UTC()

		creationDate, err := time.Parse(time.RFC3339, claims["CreationDate"].(string))
		if err != nil {
			return false, false, ""

		}


		//Getting the difference.
		//getting the difference between two times
		difference := currentTime.Sub(creationDate)
		if (difference.Hours()/24) >= MAX_DAYS_VALIDATION {

			return true, false, ""
		}

		//We got the Id and the difference is ok.
		//Returning the id and success.
		return true, true, Id

	}
		//Token not valid.
		return false, false, ""

}
