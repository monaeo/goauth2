package main

import (
	_ "github.com/go-sql-driver/mysql"
	oauth2_mysql "github.com/imrenagi/go-oauth2-mysql"
	"github.com/jmoiron/sqlx"

	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

func connectToStore() (*oauth2_mysql.ClientStore, *oauth2_mysql.TokenStore) {
	db, err := sqlx.Connect("mysql", "monaeo:monaeo@tcp(localhost:13306)/monaeo_dev?parseTime=true")
	if err != nil {
		log.Fatalln(err)
	}

	clientStore, _ := oauth2_mysql.NewClientStore(db, oauth2_mysql.WithClientStoreTableName("oauth2_clients"))
	tokenStore, _ := oauth2_mysql.NewTokenStore(db)

	return clientStore, tokenStore
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.ServeHTTP(w, r)
	})
}

func main() {
	clientStore, tokenStore := connectToStore()
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

	/*
	 * Step 1. Request Credentials: We don't really need this one, as we will provide
	 * credentials that are already created and stored. The code in this method gives us
	 * an idea on how to create credentials, and how to store them.
	 */
	http.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		clientID := uuid.New().String()[:32]

		bytes := make([]byte, 32)
		rand.Read(bytes)
		clientSecret := hex.EncodeToString(bytes)

		client := &models.Client{
			ID:     clientID,
			Secret: clientSecret,
			Domain: "http://localhost:9096",
			UserID: "1",
		}

		err := clientStore.Create(client)
		if err != nil {
			fmt.Println(err.Error())
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret})
	})

	/*
	 * Step 2. Customer Requests a token: Hit this endpoint with credentials, to get a token to make further
	 * requests.
	 */
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	})

	/*
	 * Step 3. Make a request: Notice the decorator parttern here (validateToken). We might want to somehow decouple this
	 * so that we can use it in other services, and not have to stub all requests through the oauth2 server
	 */
	http.HandleFunc("/protected", validateToken(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a protected resource"))
	}, srv))

	log.Fatal(http.ListenAndServe(":9096", nil))
}
