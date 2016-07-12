package auth

import (
	"code.google.com/p/goauth2/oauth"
	"database/sql"
	"encoding/json"
	"fmt"
	u "github.com/ChrisKaufmann/goutils"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang/glog"
	"github.com/msbranco/goconfig"
	"io/ioutil"
	"net/http"
	"time"
)

var GoogOauthCfg = &oauth.Config{
	AuthURL:    "https://accounts.google.com/o/oauth2/auth",
	TokenURL:   "https://accounts.google.com/o/oauth2/token",
	Scope:      "https://www.googleapis.com/auth/userinfo.email",
	TokenCache: oauth.CacheFile(cachefile),
}
var FBOauthCfg = &oauth.Config{ //setup
	AuthURL:  "https://www.facebook.com/dialog/oauth",
	TokenURL: "https://graph.facebook.com/oauth/access_token",
	Scope:    "",
	TokenCache: oauth.CacheFile(cachefile),
}

const profileInfoURL = "https://www.googleapis.com/oauth2/v1/userinfo"
const cachefile = "/tmp/ponytoken"

var (
	MyURL             string
	db                *sql.DB
	cookieName        string = "auth"
	environment       string = "production"
	stmtCookieIns     *sql.Stmt
	stmtInsertUser    *sql.Stmt
	stmtSessionExists *sql.Stmt
	googleEnabled     bool
	facebookEnabled   bool
)

func CookieName(c string) {
	cookieName = c
}
func Environment(e string) {
	environment = e
}
func DB(d *sql.DB) {
	db = d
	var err error
	userDB()
	stmtCookieIns, err = u.Sth(db, "INSERT INTO sessions (user_id,session_hash) VALUES( ? ,?  )")
	if err != nil {
		glog.Fatalf(" DB(): u.sth(stmtCookieIns) %s", err)
	}
	stmtInsertUser, err = u.Sth(db, "insert into users (email) values (?) ")
	if err != nil {
		glog.Fatalf(" DB(): u.sth(stmtInsertUser) %s", err)
	}
	stmtSessionExists, err = u.Sth(db, "select user_id from sessions where session_hash=?")
	if err != nil {
		glog.Fatalf(" DB(): u.sth(stmtSessionExists) %s", err)
	}
}
func Config(config string) {
	c, err := goconfig.ReadConfigFile(config)
	googleEnabled = true
	facebookEnabled = true
	if err != nil {
		glog.Fatalf("init(): readconfigfile(config)")
	}
	GoogOauthCfg.ClientId, err = c.GetString("Google", "ClientId")
	if err != nil {
		googleEnabled = false
		glog.Errorf("init(): readconfigfile(Google.ClientId)")
	}
	GoogOauthCfg.ClientSecret, err = c.GetString("Google", "ClientSecret")
	if err != nil {
		googleEnabled = false
		glog.Errorf("init(): readconfigfile(Google.ClientSecret)")
	}
	FBOauthCfg.ClientId, err = c.GetString("Facebook", "ClientId")
	if err != nil {
		facebookEnabled = false
		glog.Errorf("init(): readconfigfile(Facebook.ClientID)")
	}
	FBOauthCfg.ClientSecret, err = c.GetString("Facebook", "ClientSecret")
	if err != nil {
		facebookEnabled = false
		glog.Errorf("init(): readconfigfile(Facebook.ClientSecret)")
	}
	url, err := c.GetString("Web", "url")
	MyURL = url
	if err != nil {
		glog.Fatalf("init(): readconfigfile(Web.url)")
	}
	GoogOauthCfg.RedirectURL = url + "oauth2callback"
	FBOauthCfg.RedirectURL = url + "fboauth2callback"
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		//just means that the cookie doesn't exist or we couldn't read it
		fmt.Printf("HandleLogout: No cookie to logut %s", err)
		return
	}
	tokHash := cookie.Value
	if !SessionExists(tokHash) {
		fmt.Printf("HandleLogout: No matching sessions")
	}
	_, err = stmtLogoutSession.Exec(tokHash)
	if err != nil {
		glog.Errorf("HandleLougout: stmtLogoutSession.Exec(%s): %s", tokHash, err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// Start the authorization process
func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	//Get the Google URL which shows the Authentication page to the user
	url := GoogOauthCfg.AuthCodeURL("")

	//redirect user to that page
	http.Redirect(w, r, url, http.StatusFound)
}
func HandleAuthorizeFacebook(w http.ResponseWriter, r *http.Request) {
//	url := FBOauthCfg.AuthCodeURL("")
	url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s", FBOauthCfg.AuthURL, FBOauthCfg.ClientId, FBOauthCfg.RedirectURL)
	http.Redirect(w, r, url, http.StatusFound)
}

//simulate a demo login, create the cookie, make sure the demo user exists, create the session
func DemoUser(w http.ResponseWriter, r *http.Request) {
	demo_email := "demo@exmaple.com"
	var us User
	var err error
	if !UserExists(demo_email) {
		us, err = AddUser(demo_email)
		if err != nil {
			glog.Errorf("DemoUser(w,r)AddUser(%s): %s", demo_email, err)
			return
		}
	} else {
		us, err = GetUserByEmail(demo_email)
		if err != nil {
			glog.Errorf("DemoUser(w,r)GetUserByEmail(%s): %s", demo_email, err)
			return
		}
	}
	var authString = u.RandomString(64)
	//set the cookie
	err = us.AddSession(authString)
	if err != nil {
		glog.Errorf("DemoUser(w,r)AddUser(%s): %s", authString, err)
		return
	}
	expire := time.Now().AddDate(1, 0, 0)
	cookie := http.Cookie{Name: cookieName, Value: authString, Expires: expire}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/main.html", http.StatusFound)
}
func LoginToken(w http.ResponseWriter, r *http.Request, lt string) (err error) {
	us, err := GetUserByLoginToken(lt)
	fmt.Printf("got user: %s", us)
	if err != nil {
		glog.Errorf("LoginToken(%s) No session by that token: %s", lt, err)
		return err
	}
	var authString = u.RandomString(64)
	fmt.Printf("AddSession(%s)", authString)
	err = us.AddSession(authString)
	if err != nil {
		glog.Errorf("LoginToken():us.AddSession(%s): %s", authString, err)
		return err
	}
	expire := time.Now().AddDate(1, 0, 0)
	cookie := http.Cookie{Name: cookieName, Value: authString, Expires: expire, Path: "/"}
	fmt.Printf("http.SetCookie(w,%s)expore:%s", cookie, expire)
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/main.html", http.StatusFound)
	return err
}

// Function that handles the callback from the Google server
func HandleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	if googleEnabled == false {
		return
	}
	//Get the code from the response
	code := r.FormValue("code")

	t := &oauth.Transport{Config: GoogOauthCfg}

	// Exchange the received code for a token
	_, err := GoogOauthCfg.TokenCache.Token()
	if err != nil {
		_, err := t.Exchange(code)
		if err != nil {
			glog.Errorf("HandleOauth2Callback:GoogOauthCfg.TokenCache.Token():t.Exchange(%s): %s", code, err)
		}
	}

	// Make the request.
	req, err := t.Client().Get(profileInfoURL)
	if err != nil {
		glog.Errorf("HandleOauth2Callback:t.Client().Get(%s): %s", profileInfoURL, err)
		return
	}
	defer req.Body.Close()
	body, _ := ioutil.ReadAll(req.Body)
	//body.id is the google id to use
	//set a cookie with the id, and random hash. then save the id/hash pair to db for lookup
	var f interface{}
	err = json.Unmarshal(body, &f)
	if err != nil {
		glog.Errorf("HandleOauth2Callback:json.Unmarshal(%s): %s", body, err)
		return
	}
	err  = AddSession(w, r, f)
}
func AddSession(w http.ResponseWriter,r *http.Request,  f interface{})( err error) {
	m := f.(map[string]interface{})
	var authString = u.RandomString(64)
	email := m["email"].(string)
	var us User
	if !UserExists(email) {
		fmt.Printf("HandleOauth2Callback: creating new user %s", email)
		us, err = AddUser(email)
		if err != nil {
			glog.Errorf("HandleOauth2Callback:UserExists()AddUser(%s): %s", email, err)
		}
	} else {
		us, err = GetUserByEmail(email)
		if err != nil {
			glog.Errorf("HandleOauth2Callback:UserExists()GetUserEmail(%s): %s", email, err)
		}
	}

	err = us.AddSession(authString)

	if err != nil {
		glog.Errorf("HandleOauth2Callback:stmtCookieIns.Exec(%s,%s): %s", us.ID, authString, err)
	}
	//set the cookie
	expire := time.Now().AddDate(1, 0, 0) // year expirey seems reasonable
	cookie := http.Cookie{Name: cookieName, Value: authString, Expires: expire}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/main", http.StatusFound)
	return err
}

func HandleFacebookOauth2Callback(w http.ResponseWriter, r *http.Request) {
	if facebookEnabled == false {
		print("facebookEnabled is false, returning\n")
		return
	}
	//Get the code from the response
	code := r.FormValue("code")
	fmt.Printf("fb code = :%s\n", code)

	t := &oauth.Transport{Config: FBOauthCfg}

	// Exchange the received code for a token
	_, err := FBOauthCfg.TokenCache.Token()
	if err != nil {
		_, err := t.Exchange(code)
		if err != nil {
			glog.Errorf("HandleOauth2Callback:FBOauthCfg.TokenCache.Token():t.Exchange(%s): %s", code, err)
		}
	}
	// Make the request.
	req, err := t.Client().Get(FBOauthCfg.TokenURL)
	if err != nil {
		glog.Errorf("HandleOauth2Callback:t.Client().Get(%s): %s", FBOauthCfg.TokenURL, err)
		return
	}
	defer req.Body.Close()
	body, _ := ioutil.ReadAll(req.Body)
	//body.id is the  id to use
	//set a cookie with the id, and random hash. then save the id/hash pair to db for lookup
	var f interface{}
	err = json.Unmarshal(body, &f)
	if err != nil {
		glog.Errorf("HandleOauth2Callback:json.Unmarshal(%s): %s", body, err)
		return
	}
	err  = AddSession(w, r, f)

	return
}


func LoggedIn(w http.ResponseWriter, r *http.Request) (bool, User) {
	var falseuser User
	if environment == "test" {
		tue := "test@example.com"
		fmt.Printf("Test login")
		if !UserExists(tue) {
			us, err := AddUser(tue)
			if err != nil {
				glog.Errorf("Couldn't add user: %s", err)
				return false, falseuser
			}
			return true, us
		} else {
			us, err := GetUserByEmail(tue)
			if err != nil {
				glog.Errorf("Couldn't get user by email: %s", err)
				return false, falseuser
			}
			return true, us
		}
	}
	cookie, err := r.Cookie(cookieName)
	switch {
	case err == http.ErrNoCookie: // just means cookie doesn't exist or we couldn't read
		fmt.Printf("Couldn't get cookie")
		return false, falseuser
	case err != nil:
		glog.Errorf("Loggedin() r.Cookie(%s): %s", cookieName, err)
		return false, falseuser
	}
	tokHash := cookie.Value
	if !SessionExists(tokHash) {
		fmt.Printf("SessionExists(%s) is false", tokHash)
		return false, falseuser
	}
	us, err := GetUserBySession(tokHash)
	if err != nil {
		glog.Errorf("LoggedIn():GetUserBySession(%s): %s", tokHash, err)
		return false, falseuser
	}
	if us.ID > 0 {
		return true, us
	}
	fmt.Printf("UID: %s, returning false", us.ID)
	return false, falseuser
}
