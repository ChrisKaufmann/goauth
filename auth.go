package auth

import (
	"golang.org/x/oauth2"
	fboauth "golang.org/x/oauth2/facebook"
	googleoauth "golang.org/x/oauth2/google"
	"database/sql"
	"encoding/json"
	"fmt"
	u "github.com/ChrisKaufmann/goutils"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang/glog"
	"github.com/msbranco/goconfig"
	"io/ioutil"
	//"net/url"
	"net/http"
	"time"
)


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
	GoogOauthCfg = &oauth2.Config{
		ClientID:	"",
		ClientSecret: "",
		Scopes: []string{"https://www.googleapis.com/auth/userinfo.email",},
		Endpoint: googleoauth.Endpoint,
	}
	FBOauthCfg = &oauth2.Config {
		ClientID:	"",
		ClientSecret: "",
		Scopes: []string{"email"},
		Endpoint: fboauth.Endpoint,
	}
	oauthStateString = u.RandomString(32)
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
	GoogOauthCfg.ClientID, err = c.GetString("Google", "ClientID")
	if err != nil {
		googleEnabled = false
		glog.Errorf("init(): readconfigfile(Google.ClientID)")
	}
	GoogOauthCfg.ClientSecret, err = c.GetString("Google", "ClientSecret")
	if err != nil {
		googleEnabled = false
		glog.Errorf("init(): readconfigfile(Google.ClientSecret)")
	}
	FBOauthCfg.ClientID, err = c.GetString("Facebook", "ClientID")
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
	url := FBOauthCfg.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)

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
func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if googleEnabled == false {
		return
	}
	authcode := r.FormValue("code")

	tok, err := GoogOauthCfg.Exchange(oauth2.NoContext, authcode)
	if err != nil {
		fmt.Println("err is", err)
	}

	fmt.Println("token is ", tok)
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + tok.AccessToken)

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	fmt.Printf("contents: %s", contents)
	var f interface{}
	err = json.Unmarshal(contents, &f)
	if err != nil {
		glog.Errorf("json.Unmarshal(%s,f): %s\n", contents, err)
	}
	m := f.(map[string]interface{})
	email := m["email"].(string)
	err  = AddSession(w, r, email)
	if err != nil {
		glog.Errorf("AddSession(w,r,%s): %s\n", email, err)
	}
	return
}
func AddSession(w http.ResponseWriter,r *http.Request,  email string)( err error) {
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
	var authString = u.RandomString(64)


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
	authcode := r.FormValue("code")
	type fbuser struct {
		Id  string `json:"id"`
		Name string `json:"name"`
	}

	tok, err := FBOauthCfg.Exchange(oauth2.NoContext, authcode)
	if err != nil {
		glog.Errorf("FBOauthCfg.Exchange(oauth2.NoContext, %s): %s", authcode, err)
		return
	}

	response, err := http.Get("https://graph.facebook.com/me?access_token=" + tok.AccessToken)
	if err != nil {
		glog.Errorf("http.Get(https://graph.facebook.com/me?access_token=%s): %s", tok.AccessToken, err)
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		glog.Errorf("ioutil.ReadAll(%s): %s", response.Body, err)
		return
	}

	var fbu fbuser
	err = json.Unmarshal(body, &fbu)
	if err != nil {
		glog.Errorf("json.Unmarshal(%s, fbu): %s", body, err)
		return
	}
	email := fmt.Sprintf("%s@facebook.com", fbu.Id)

	err = AddSession(w,r,email)
	if err != nil {
		glog.Errorf("AddSession(w,r,%s): %s", email, err)
		return
	}
}
func GetFromURL(u string) (j string, err error) {
	fmt.Printf("GetJsonFromURL(%s)\n", u)
	resp, err := http.Get(u)
	if err != nil {
		glog.Errorf("http.Get(%s): %s", u, err)
		return j, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("ioutil.ReadAll(resp.Body): %s", err)
	}
	s := string(body[:])
	return s, err
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