package auth

import (
	"testing"
)

// const te = "user@example.com" //imported from user

func TestAuth(t *testing.T) {
	initTest(t) //creates a blank DB to play with
	print("Testing Auth\n")

	//Add a user
	print("\tAddUser\n")
	u1, err := AddUser(te)
	if err != nil {
		t.Errorf("AddUser(%s): %s", te, err)
	}

	//And a session
	print("\tAddSession\n")
	err = u1.AddSession("my new session")
	if err != nil {
		t.Errorf("user.AddSession(%s): %s", "my new session", err)
	}

}
