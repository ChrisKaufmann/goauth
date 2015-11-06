package auth

import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
    "github.com/msbranco/goconfig"
	"testing"
	"fmt"
	"errors"
    u "github.com/ChrisKaufmann/goutils"
)

const te = "user@example.com"
const sid = "myreallylongsessioncodegoeshereandisrealllllylongok?"

func TestUser(t *testing.T) {
	initTest(t) //creates a blank DB to play with
	print("Testing User\n")

	//check UserExists when false
	print("\tNon-Existing UserExists()\n")
	if UserExists(te) {t.Errorf("User shouldn't exist")}

	//Adduser
	print("\tAddUser()\n")
	_, err := AddUser(te)
	if err != nil {t.Errorf("AddUser(%s): %s", te, err)}

	//check UserExists when true
	print("\tExisting UserExists()\n")
	if !UserExists(te){t.Errorf("User %s should now exist", te)}

	//getuser by email
	print("\tGetUserByEmail\n")
	gube, err := GetUserByEmail(te)
	if err != nil {t.Errorf("GetUserByEmail(%s): %s", te, err)}
	if gube.Email != te {t.Errorf("GetUserByEmail(%s).User doesn't match, got %s", te, gube.Email)}

	//get by id
	print("\tGetUserByID\n")
	u1, err := GetUserByEmail(te)
	if err != nil {t.Errorf("GetUserByEmail(%s): %s", te, err)}
	u2, err := GetUser(u1.ID)
	if err != nil {t.Errorf("GetUser(%v): %s", u1.ID, err)}
	if u2.Email != te {t.Errorf("Mismatch, u2: %s, expected: %s",u2.Email, te)}

	//Add a session
	print("\tUser.AddSession\n")
	err = u2.AddSession(sid)
	if err != nil {t.Errorf("user.AddSession(%s): %s", sid, err)}

	//get by session
	print("\tGetUserBySession\n")
	u3, err := GetUserBySession(sid)
	if err != nil {t.Errorf("GetUserBySession(%s): %s", sid, err)}
	if u3.Email != te {t.Errorf("Mismatch, u3.Email: %s, expected: %s", u3.Email, te)}

	//Session exists (t/f)
	print("\tSessionExists\n")
	if !SessionExists(sid) {t.Errorf("No session for %s", sid)}
	if SessionExists("oh") {t.Errorf("Session shouldn't exist for dummy session 'oh'")}

	//get sharecode
	print("\tuser.ShareCode()\n")
	usc := u1.ShareCode()
	if len(usc) < 1 {t.Errorf("Bad user.Sharecode: %s", usc)}

	//new sharecode
	print("\tuser.NewShareCode()\n")
	nsc := u1.NewShareCode()
	if usc == nsc {t.Errorf("New sharecode shouldn't match old: %s <=> %s", nsc, usc)}
	//and verify it
	tsc := u1.ShareCode()
	if tsc != nsc {t.Errorf("New sharecode doesn't match retrieved: %s <=> %s", nsc, tsc)}

	//logincode
	print("\tuser.LoginCode()\n")
	ulc := u1.LoginCode()
	if len(ulc) < 1 {t.Errorf("Bad user.LoginCode(): %s", ulc)}

	//new logincode
	print("\tuser.NewLoginCode()\n")
	nlc := u1.NewLoginCode()
	if ulc == nlc {t.Errorf("New logincode shouldn't match old: %s <=> %s", nlc, ulc)}
	//and verify it
	tlc := u1.LoginCode()
	if tlc != nlc {t.Errorf("New logincode doesn't match retrieved: %s <=> %s", nlc, tlc)}

	//get by shared
	print("\tGetUserByShared()\n")
	u4, err := GetUserByShared(tsc)
	if err != nil {t.Errorf("GetUserByShared(%s): %s", tsc, err)}
	if u4.Email != te {t.Errorf("Wrong user by shared code: %s expected %s", u4.Email, te)}

	//get by logintoken
	print("\tGetUserByLoginToken\n")
	u5, err := GetUserByLoginToken(tlc)
	if err != nil {t.Errorf("GetUserByLoginToken(%s): %s", tlc, err)}
	if u5.Email != te {t.Errorf("Wrong user by logintoken: %s, expected %s", u5.Email, te)}

}
func vl(t *testing.T,s string, e interface{}, a interface{}) {
    if e != a {
        err := errors.New("expected: "+u.Tostr(e)+" got: "+u.Tostr(a)+"\n")
        t.Errorf(s, err)
    }
}
func ec(t *testing.T,s string, err error) {
    if err != nil {
        t.Errorf(s, err)
    }
}
func initTest(t *testing.T)  {
    c, err := goconfig.ReadConfigFile("config")
    db_name, err := c.GetString("DB", "db")
    if err != nil {
        err.Error();fmt.Println(err)
    }
    db_host, err := c.GetString("DB", "host")
    if err != nil {
        err.Error();fmt.Println(err)
    }
    db_user, err := c.GetString("DB", "user")
    if err != nil {
        err.Error();fmt.Println(err)
    }
    db_pass, err := c.GetString("DB", "pass")
    if err != nil {
        err.Error();fmt.Println(err)
    }
    db, err = sql.Open("mysql", db_user+":"+db_pass+"@"+db_host+"/"+db_name)
    if err != nil {
        panic(err)
    }
    _,err = db.Query("Drop table if exists users;")
    ec(t,"drop table things",err)
	_,err = db.Query("create table `users` (id int unsigned primary key not null auto_increment,email varchar(128),share_token char(128),login_token char(128));")
	ec(t,"create table users", err)
    _,err = db.Query("Drop table if exists sessions;")
    ec(t,"drop table sessions",err)
	_,err = db.Query("create table sessions (	user_id varchar(255) NOT NULL,	session_hash char(255) NOT NULL PRIMARY KEY);")
	ec(t,"create table sessions", err)
	DB(db)
}
