package auth

//  auth/user.go

import (
	"database/sql"
	"errors"
	"fmt"
	u "github.com/ChrisKaufmann/goutils"
	"github.com/golang/glog"
)

type User struct {
	ID    int
	Email string
	Admin bool
}

var (
	stmtInsertUserShare    *sql.Stmt
	stmtInsertUserLogin    *sql.Stmt
	stmtGetUserShare       *sql.Stmt
	stmtGetUserLogin       *sql.Stmt
	stmtGetUserID          *sql.Stmt
	stmtGetUserBySession   *sql.Stmt
	stmtGetUserByShared    *sql.Stmt
	stmtGetUserByID        *sql.Stmt
	stmtGetUserByLoginCode *sql.Stmt
	stmtLogoutSession      *sql.Stmt
	stmtSetAdmin           *sql.Stmt
	stmtGetAllUsers		*sql.Stmt
)

func userDB() {
	var err error

	scst := "create table  if not exists `sessions` ( `user_id` varchar(255) NOT NULL, `session_hash` char(255) NOT NULL, PRIMARY KEY (`session_hash`)) ;"
	_, err = db.Exec(scst)
	if err != nil {
		glog.Fatalf("db.Exec(%s): %s", scst, err)
	}

	scut := "create table if not exists `users` ( `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `email` varchar(128) DEFAULT NULL, `admin` bool DEFAULT false, `share_token` char(128) DEFAULT NULL, `login_token` char(128) DEFAULT NULL, PRIMARY KEY (`id`))"
	_, err = db.Exec(scut)
	if err != nil {
		glog.Fatalf("db.Exec(%s): %s", scut, err)
	}

	sius := "update users set share_token=? where id=?"
	stmtInsertUserShare, err = u.Sth(db, sius)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sius, err)
	}

	sgus := "select ifnull(share_token,'') from users where id = ?"
	stmtGetUserShare, err = u.Sth(db, sgus)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sgus, err)
	}

	siul := "update users set login_token=? where id=?"
	stmtInsertUserLogin, err = u.Sth(db, siul)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", siul, err)
	}

	sgul := "select ifnull(login_token,'') from users where id=?"
	stmtGetUserLogin, err = u.Sth(db, sgul)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sgul, err)
	}

	sguid := "select id,admin from users where email = ?"
	stmtGetUserID, err = u.Sth(db, sguid)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sguid, err)
	}

	sls := "delete from sessions where session_hash=? limit 1"
	stmtLogoutSession, err = u.Sth(db, sls)
	if err != nil {
		glog.Fatalf(" DB(): u.sth(%s) %s", sls, err)
	}

	sgubs := "select users.id, users.email, IFNULL(users.admin,false) from users, sessions where users.id=sessions.user_id and sessions.session_hash=?"
	stmtGetUserBySession, err = u.Sth(db, sgubs)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sgubs, err)
	}

	sgubsh := "select id, email, IFNULL(admin,false) from users where share_token = ?"
	stmtGetUserByShared, err = u.Sth(db, sgubsh)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sgubsh, err)
	}

	sgubid := "select ID,Email,admin from users where id=?"
	stmtGetUserByID, err = u.Sth(db, sgubid)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sgubid, err)
	}

	sgublc := "select id, email, admin from users where login_token = ?"
	stmtGetUserByLoginCode, err = u.Sth(db, sgublc)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", sgublc, err)
	}

	ssa := "update users set admin=? where id=? limit 1"
	stmtSetAdmin, err = u.Sth(db, ssa)
	if err != nil {
		glog.Fatalf("u.Sth(%s): %s", ssa, err)
	}

	sga := "select id, email, admin from users where 1"
	stmtGetAllUsers, err = u.Sth(db,sga)
	if err != nil {
		glog.Fatalf("u.Sth(db, %s): %s", sga, err)
	}

}

//object functions
func (us User) String() string {
	return fmt.Sprintf("ID: %v\nEmail: %s\nAdmin: %v", us.ID, us.Email, us.Admin)
}
func (us User) AddSession(sh string) (err error) {
	_, err = stmtCookieIns.Exec(us.ID, sh)
	if err != nil {
		glog.Errorf("user.AddSession(%s)stmtCookieIns(%s,%s):%s", us, us.ID, sh, err)
	}
	return err
}
func (us User) SetAdmin(tf bool) (err error) {
	_, err = stmtSetAdmin.Exec(tf, us.ID)
	if err != nil {
		glog.Errorf("user.SetAdmin()-stmtSetAdmin(%v, %v): %s", tf, us.ID, err)
	}
	return err
}
func (us User) DeleteSession(sh string) (err error) {
	_, err = stmtLogoutSession.Exec(sh)
	if err != nil {
		glog.Errorf("user.DeleteSession()-stmtLogoutSession(%s): %s", sh, err)
	}
	return err
}
func (us User) ShareCode() string {
	var sc string
	err := stmtGetUserShare.QueryRow(us.ID).Scan(&sc)
	switch {
	case err == sql.ErrNoRows || sc == "":
		glog.Infof("No existing share code")
		newstr := u.RandomString(128)
		_, err := stmtInsertUserShare.Exec(newstr, us.ID)
		if err != nil {
			glog.Errorf("stmtInsertUserShare.Exec(%s,%s): %s", us.ID, newstr, err)
			return ""
		}
		return newstr
	case err != nil:
		glog.Errorf("stmtGetUserShare.QueryRow(%s): %s", us.ID, err)
		return ""
	}
	return sc
}
func (us User) NewShareCode() string {
	newstr := u.RandomString(128)
	_, err := stmtInsertUserShare.Exec(newstr, us.ID)
	if err != nil {
		glog.Errorf("stmtInsertUserShare.Exec(%s,%s): %s", us.ID, newstr, err)
		return ""
	}
	return us.ShareCode()
}
func (us User) LoginCode() (lc string) {
	err := stmtGetUserLogin.QueryRow(us.ID).Scan(&lc)
	switch {
	case err == sql.ErrNoRows || lc == "":
		glog.Infof("No existing login code")
		newstr := u.RandomString(128)
		_, err := stmtInsertUserLogin.Exec(newstr, us.ID)
		if err != nil {
			glog.Errorf("stmtInsertUserLogin(%s,%s): %s", newstr, us.ID, err)
			return ""
		}
		return newstr
	case err != nil:
		glog.Errorf("stmtGetLoginShare.QueryRow(%s): %s", us.ID, err)
		return ""
	}
	return lc
}
func (us User) NewLoginCode() string {
	newstr := u.RandomString(128)
	_, err := stmtInsertUserLogin.Exec(newstr, us.ID)
	if err != nil {
		glog.Errorf("stmtInsertUserLogin(%s,%s): %s", newstr, us.ID, err)
		return ""
	}
	return us.LoginCode()
}

//Non object functions
func UserExists(email string) (exists bool) {
	var u User
	err := stmtGetUserID.QueryRow(email).Scan(&u.ID, &u.Admin)
	switch {
	case err == sql.ErrNoRows:
		exists = false
	case err != nil:
		glog.Errorf("UserExists():stmtGetUserID(%s): %s", email, err)
		exists = false
	default:
		exists = true
	}
	return exists
}
func AddUser(e string) (us User, err error) {
	if UserExists(e) {
		err = stmtGetUserID.QueryRow(e).Scan(&us.ID, &us.Admin)
		return us, err
	}
	result, err := stmtInsertUser.Exec(e)
	if err != nil {
		glog.Errorf("AddUser(%s): %s", e, err)
		return us, err
	}
	lid, err := result.LastInsertId()
	us.ID = int(lid)
	us.Email = e
	return us, err
}
func GetUserByEmail(e string) (us User, err error) {
	if !UserExists(e) {
		err = errors.New("User Doesn't exist")
		glog.Errorf("GetUserByEmail(%s): %s", e, err)
		return us, err
	}
	err = stmtGetUserID.QueryRow(e).Scan(&us.ID, &us.Admin)
	if err != nil {
		glog.Errorf("GetUserByEmail()stmtGetUserID(%s): %s", e, err)
	}
	us.Email = e
	return us, err
}
func GetUser(id int) (us User, err error) {
	err = stmtGetUserByID.QueryRow(id).Scan(&us.ID, &us.Email, &us.Admin)
	switch {
	case err == sql.ErrNoRows:
		err = errors.New("No user")
		return us, err
	case err != nil:
		glog.Errorf("GetUserBySession():stmtGetUserByID(%s): %s", id, err)
		return us, err
	}
	return us, err
}
func GetUserBySession(s string) (us User, err error) {
	err = stmtGetUserBySession.QueryRow(s).Scan(&us.ID, &us.Email, &us.Admin)
	switch {
	case err == sql.ErrNoRows:
		err = errors.New("No valid session")
		return us, err
	case err != nil:
		glog.Errorf("GetUserBySession():stmtGetUserBySession(%s): %s", s, err)
		return us, err
	}
	return us, err
}
func GetUserByShared(s string) (us User, err error) {
	err = stmtGetUserByShared.QueryRow(s).Scan(&us.ID, &us.Email, &us.Admin)
	switch {
	case err == sql.ErrNoRows:
		err = errors.New("No valid session")
		return us, err
	case err != nil:
		glog.Errorf("GetUserBySession():stmtGetUserBySession(%s): %s", s, err)
		return us, err
	}
	return us, err
}
func GetUserByLoginToken(s string) (us User, err error) {
	err = stmtGetUserByLoginCode.QueryRow(s).Scan(&us.ID, &us.Email, &us.Admin)
	switch {
	case err == sql.ErrNoRows:
		glog.Errorf("GetUserByLoginToken(s):stmtGetUserByLoginCode(%s):%s", s, err)
		err = errors.New("No valid session")
		return us, err
	case err != nil:
		glog.Errorf("GetUserByLoginCode():stmtGetUserByLoginCode(%s): %s", s, err)
		return us, err
	}
	return us, err
}
func SessionExists(s string) (e bool) {
	var uid int
	err := stmtSessionExists.QueryRow(s).Scan(&uid)
	switch {
	case err == sql.ErrNoRows:
		return false
	case err != nil:
		glog.Errorf("SessionExists():stmtSessionExists(%s): %s", s, err)
		return false
	default:
		return true
	}
	return e
}
func AllUsers() (ul []User, err error) {
	rows, err := stmtGetAllUsers.Query()
	if err != nil {
		glog.Errorf("stmtGetAllUsers.Query(): %s", err)
		return ul, err
	}
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Email, &u.Admin)
		ul = append(ul, u)
	}
	return ul, err
}
