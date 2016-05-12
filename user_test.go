package auth

import (
	"database/sql"
	"errors"
	"fmt"
	u "github.com/ChrisKaufmann/goutils"
	_ "github.com/go-sql-driver/mysql"
	"github.com/msbranco/goconfig"
	"testing"
)

const te = "user@example.com"
const sid = "myreallylongsessioncodegoeshereandisrealllllylongok?"

func TestUser_SetAdmin(t *testing.T) {
	print("User.SetAdmin\n")
	initTest(t)
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	if err := u.SetAdmin(true); err != nil {
		t.Errorf("u.SetAdmin(true): %s", err)
	}
	u, err = GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	if u.Admin != true {
		t.Errorf("u.Admin true <=> %v", false)
	}
}
func TestUser_AddSession(t *testing.T) {
	initTest(t)
	print("User.AddSession\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	if err := u.AddSession("session that shouldn't exist"); err != nil {
		t.Errorf("user.AddSession(%s): %s", "session that shouldn't exist", err)
	}
}
func TestUser_DeleteSession(t *testing.T) {
	initTest(t)
	print("User.DeleteSession\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	err = u.DeleteSession(sid)
	if err != nil {
		t.Errorf("u1.DeleteSession(%s): %s", sid, err)
	}
	if SessionExists(sid) {
		t.Errorf("Session still exists after deleting!")
	}

}
func TestUser_LoginCode(t *testing.T) {
	initTest(t)
	print("User.LoginCode\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	ulc := u.LoginCode()
	if len(ulc) < 1 {
		t.Errorf("Bad user.LoginCode(): %s", ulc)
	}
}
func TestUser_NewLoginCode(t *testing.T) {
	initTest(t)
	print("User.NewLoginCode\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	ulc := u.LoginCode()
	nlc := u.NewLoginCode()
	if ulc == nlc {
		t.Errorf("New logincode shouldn't match old: %s <=> %s", nlc, ulc)
	}
	//and verify it
	tlc := u.LoginCode()
	if tlc != nlc {
		t.Errorf("New logincode doesn't match retrieved: %s <=> %s", nlc, tlc)
	}

}
func TestUser_ShareCode(t *testing.T) {
	initTest(t)
	print("User.ShareCode\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	usc := u.ShareCode()
	if len(usc) < 1 {
		t.Errorf("Bad user.Sharecode: %s", usc)
	}

}
func TestUser_NewShareCode(t *testing.T) {
	initTest(t)
	print("User.NewShareCode\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	usc := u.ShareCode()
	if len(usc) < 1 {
		t.Errorf("Bad user.Sharecode: %s", usc)
	}
	nsc := u.NewShareCode()
	if usc == nsc {
		t.Errorf("New sharecode shouldn't match old: %s <=> %s", nsc, usc)
	}
	//and verify it
	tsc := u.ShareCode()
	if tsc != nsc {
		t.Errorf("New sharecode doesn't match retrieved: %s <=> %s", nsc, tsc)
	}

}

func TestGetUserBySession(t *testing.T) {
	initTest(t)
	print("GetUserBySession\n")
	u3, err := GetUserBySession(sid)
	if err != nil {
		t.Errorf("GetUserBySession(%s): %s", sid, err)
	}
	if u3.Email != te {
		t.Errorf("Mismatch, u3.Email: %s, expected: %s", u3.Email, te)
	}

}
func TestGetUserByShared(t *testing.T) {
	initTest(t)
	print("GetUserByShared\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	tsc := u.ShareCode()
	u4, err := GetUserByShared(tsc)
	if err != nil {
		t.Errorf("GetUserByShared(%s): %s", tsc, err)
	}
	if u4.Email != te {
		t.Errorf("Wrong user by shared code: %s expected %s", u4.Email, te)
	}
}
func TestUserExists(t *testing.T) {
	initTest(t)
	print("UserExists\n")
	if UserExists("user that shouldn't exist") {
		t.Errorf("user shouldn't exist")
	}
	if !UserExists(te) {
		t.Errorf("User %s doesn't exist", te)
	}
}
func TestGetUserByLoginToken(t *testing.T) {
	initTest(t)
	print("GetUserByLoginCode\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	tlc := u.LoginCode()
	u5, err := GetUserByLoginToken(tlc)
	if err != nil {
		t.Errorf("GetUserByLoginToken(%s): %s", tlc, err)
	}
	if u5.Email != te {
		t.Errorf("Wrong user by logintoken: %s, expected %s", u5.Email, te)
	}

}
func TestAddUser(t *testing.T) {
	initTest(t)
	print("AddUser\n")
	nee := "new user email"
	_, err := AddUser(nee)
	if err != nil {
		t.Errorf("AddUser(%s): %s", nee, err)
	}
	u, err := GetUserByEmail(nee)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", nee, err)
	}
	if u.Email != nee {
		t.Errorf("Email doesn't match %s <=> %s", nee, u.Email)
	}
}
func TestGetUser(t *testing.T) {
	initTest(t)
	print("GetUser\n")
	u, err := GetUser(1)
	if err != nil {
		t.Errorf("GetUser(1): %s", err)
	}
	if len(u.Email) < 1 {
		t.Errorf("Invalid email for GetUser(1)")
	}
	if u.Admin != false {
		t.Errorf("GetUserByEmail(%s).Admin false <=> %v", te, u.Admin)
	}
}
func TestGetUserByEmail(t *testing.T) {
	initTest(t)
	print("GetUserByEmail\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	if u.Email != te {
		t.Errorf("GetUserByEmail(%s).Email <=> %s", te, u.Email)
	}
	if u.Admin != false {
		t.Errorf("GetUserByEmail(%s).Admin false <=> %v", te, u.Admin)
	}
	if u.ID < 1 {
		t.Errorf("Invalid user.ID: %v", u.ID)
	}
}
func TestSessionExists(t *testing.T) {
	initTest(t)
	print("SessionExists\n")
	u, err := GetUserByEmail(te)
	if err != nil {
		t.Errorf("GetUserByEmail(%s): %s", te, err)
	}
	if SessionExists("shoudln'texist") {
		t.Errorf("SessionExists(shouldn't exist) shouldn't exist")
	}
	u.AddSession("Now it should exist")
	if !SessionExists("Now it should exist") {
		t.Errorf("SessionExists(Now it should exist) doesn't exist")
	}
}
func vl(t *testing.T, s string, e interface{}, a interface{}) {
	if e != a {
		err := errors.New("expected: " + u.Tostr(e) + " got: " + u.Tostr(a) + "\n")
		t.Errorf(s, err)
	}
}
func ec(t *testing.T, s string, err error) {
	if err != nil {
		t.Errorf(s, err)
	}
}
func initTest(t *testing.T) {
	c, err := goconfig.ReadConfigFile("config")
	db_name, err := c.GetString("DB", "db")
	if err != nil {
		err.Error()
		fmt.Println(err)
	}
	db_host, err := c.GetString("DB", "host")
	if err != nil {
		err.Error()
		fmt.Println(err)
	}
	db_user, err := c.GetString("DB", "user")
	if err != nil {
		err.Error()
		fmt.Println(err)
	}
	db_pass, err := c.GetString("DB", "pass")
	if err != nil {
		err.Error()
		fmt.Println(err)
	}
	db, err = sql.Open("mysql", db_user+":"+db_pass+"@"+db_host+"/"+db_name)
	if err != nil {
		panic(err)
	}
	_, err = db.Query("Drop table if exists users;")
	ec(t, "drop table things", err)
	_, err = db.Query("Drop table if exists sessions;")
	ec(t, "drop table sessions", err)
	DB(db)
	userDB()
	_, err = AddUser("a")
	_, err = AddUser("1")
	_, err = AddUser("2")
	_, err = AddUser("3")
	_, err = AddUser("4")
	_, err = AddUser("5")
	_, err = AddUser("6")
	_, err = AddUser("7")
	_, err = AddUser("8")
	_, err = AddUser("9")
	_, err = AddUser("0")
	_, err = AddUser(te)
	u, err := GetUserByEmail(te)
	if err := u.AddSession(sid); err != nil {
		t.Errorf("user.AddSession(%s): %s", sid, err)
	}
}
