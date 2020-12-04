package handler

import (
	"fmt"
	"log"
	"net/http"

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

//ConnectToStores handles connecting to the database where the client and toke store will live
func ConnectToStores(storeConfig Goauth2StoreConfig) (*oauth2_mysql.ClientStore, *oauth2_mysql.TokenStore, error) {
	var clientStore *oauth2_mysql.ClientStore
	var tokenStore *oauth2_mysql.TokenStore
	db, err := sqlx.Connect("mysql",
		fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
			storeConfig.DBUser,
			storeConfig.DBPass,
			storeConfig.DBHost,
			storeConfig.DBPort,
			storeConfig.DBSchema,
		),
	)

	if err != nil {
		clientStore, _ = oauth2_mysql.NewClientStore(db, oauth2_mysql.WithClientStoreTableName(storeConfig.ClientTableName))
		tokenStore, _ = oauth2_mysql.NewTokenStore(db, oauth2_mysql.WithTokenStoreTableName(storeConfig.TokenTableName))
	}

	return clientStore, tokenStore, err
}

// InitializeWithStores initializes the oauth2 server runtime with configured client and token stores
func InitializeWithStores(clientStore *oauth2_mysql.ClientStore, tokenStore *oauth2_mysql.TokenStore) *server.Server {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	manager.MustTokenStorage(store.NewMemoryTokenStore())

	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	return srv
}

// HandleTokenRequest stubs to oauth2 server a request for a token
func HandleTokenRequest(srv *server.Server, w http.ResponseWriter, r *http.Request) {
	srv.HandleTokenRequest(w, r)
}

// HandleOAuth2Routes handles authentication endpoints
func HandleOAuth2Routes(server *server.Server) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	r.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		HandleTokenRequest(server, w, r)
	})

	return r
}

// UseAuthentication validates a token, given one in a request
func UseAuthentication(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.ServeHTTP(w, r)
	})
}
