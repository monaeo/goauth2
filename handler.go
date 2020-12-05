package handler

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	oauth2_mysql "github.com/imrenagi/go-oauth2-mysql"
	"github.com/jmoiron/sqlx"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

// Goauth2StoreConfig specifies the configuration required by the stores
type Goauth2StoreConfig struct {
	DBSchema        string
	DBUser          string
	DBPass          string
	DBHost          string
	DBPort          string
	ClientTableName string
	TokenTableName  string
}

var (
	oauth2Srv *server.Server
	once      sync.Once
)

//ConnectToStores handles connecting to the database where the client and toke store will live
func ConnectToStores(storeConfig Goauth2StoreConfig) (*oauth2_mysql.ClientStore, *oauth2_mysql.TokenStore, error) {
	var clientStore *oauth2_mysql.ClientStore
	var tokenStore *oauth2_mysql.TokenStore
	url := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true",
		storeConfig.DBUser,
		storeConfig.DBPass,
		storeConfig.DBHost,
		storeConfig.DBPort,
		storeConfig.DBSchema,
	)

	db, err := sqlx.Connect("mysql", url)

	if err != nil {
		return nil, nil, err
	}

	clientStore, _ = oauth2_mysql.NewClientStore(db, oauth2_mysql.WithClientStoreTableName(storeConfig.ClientTableName))
	tokenStore, _ = oauth2_mysql.NewTokenStore(db, oauth2_mysql.WithTokenStoreTableName(storeConfig.TokenTableName))

	return clientStore, tokenStore, err
}

// InitializeWithStores initializes the oauth2 server runtime with configured client and token stores
func InitializeWithStores(clientStore *oauth2_mysql.ClientStore, tokenStore *oauth2_mysql.TokenStore) {
	once.Do(func() {
		manager := manage.NewDefaultManager()
		manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

		manager.MustTokenStorage(store.NewMemoryTokenStore())

		manager.MapClientStorage(clientStore)
		manager.MapTokenStorage(tokenStore)

		oauth2Srv = server.NewDefaultServer(manager)
		oauth2Srv.SetAllowGetAccessRequest(true)
		oauth2Srv.SetClientInfoHandler(server.ClientFormHandler)
		manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

		oauth2Srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
			log.Println("Internal Error:", err.Error())
			return
		})

		oauth2Srv.SetResponseErrorHandler(func(re *errors.Response) {
			log.Println("Response Error:", re.Error.Error())
		})
	})
}

// AddOAuth2Routes handles authentication endpoints
func AddOAuth2Routes(path string, r *mux.Router) *mux.Router {

	// Handle a Token request i.e. http://localhost/token?grant_type=client_credentials&client_id=000000&client_secret=999999&scope=read
	r.HandleFunc(fmt.Sprintf("%s/token", path), func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Handle /token route?\n")
		oauth2Srv.HandleTokenRequest(w, r)
	})

	return r
}

// UseAuthentication validates a token, given one in a request
func UseAuthentication(f http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := oauth2Srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.ServeHTTP(w, r)
	})
}
