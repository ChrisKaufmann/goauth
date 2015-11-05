Yes, yet another goauth.

I want google auth, facebook auth, twitter auth, and to return a super simple user.

Really for my own use/fun

```
import auth "github.com/chriskaufmann/goauth"
import "fmt"

func init() {
auth.Config("configfile")
auth.CookieName("cookie name")
auth.Environment("demo/dev/whatevs")
}

func main() {
	auth.DB(db_handle)
    http.HandleFunc("/authorize", auth.HandleAuthorize)
    http.HandleFunc("/oauth2callback", auth.HandleOAuth2Callback)
    http.HandleFunc("/logout", auth.HandleLogout)
}

func myhandler(w http.ResponseWriter, r *http.Request) {
	loggedin, user = auth.LoggedIn(w,r)
	if !loggedin {
		return
	}
	fmt.Printf("Email: %s, ID: %s, ShareCode: %s, LoginCode: %s, user.Email, user.ID, user.ShareCode, usr.LoginCode)
	if UserExists("email") { print("yay!") }
	newuser, err := auth.AddUser("Email@example.com")
	if err != nil {return}
	userbyemail, err := auth.UserByEmail("user@example.com")
	if err != nil {return}
	id := 1
	userbyid, err := auth.GetUser(id)
	if err != nil {return}
	session := "my long session code, perhaps from a cookie"
	if !auth.SessionExists(session) { print("No existing session for this code") }
	userbysession, err := auth.GetUserBySession(session)
	if err != nil {return}
	shared := "my sharing code, perhaps from cookie or link"
	userbyshared, err := auth.GetUserByShared(shared)
	if err != nil {return}
	logintoken := "my long login token, perhaps from cookie or link"
	userbylogin, err := auth.GetUserByLoginToken(logintoken)
	if err != nil {return}
}
func handledemo(w http.ResponseWriter, r *http.Request) {
	auth.DemoUser(w,r) //creates a demo user session
}
```
