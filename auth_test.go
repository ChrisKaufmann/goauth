package auth

import (
	"testing"
	"net/http"
	"github.com/stvp/assert"
	"net/http/httptest"
)

// const te = "user@example.com" //imported from user
var (
	w = httptest.NewRecorder()
	r = http.Request{}
)

func TestAuth(t *testing.T) {
	initTest(t) //creates a blank DB to play with
	print("Testing Auth\n")
}

func TestAddSession(t *testing.T) {
	print("AddSession\n")
	initTest(t)

	err := AddSession(w,&r,te)
	assert.Nil(t,err,"AddSession(w,r,te")
}