package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"http-rest-api/internal/app/model/roles"
	"http-rest-api/internal/app/model/users"
	"http-rest-api/internal/app/store"
	"os"

	// "http-rest-api/internal/app/apiserver/apiserver.go"

	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	ctxKeyUser ctxKey = iota
	ctxKeyRequestID
)

var (
	jwtKey = []byte(os.Getenv("SECRET_KEY"))
)

type ctxKey int8

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	RoleID string `json:"role_id"`
	Email  string `json:"email"`
	jwt.StandardClaims
}

type server struct {
	router       *mux.Router
	logger       *logrus.Logger
	store        store.Store
	sessionStore sessions.Store
}

func newServer(store store.Store, sessionStore sessions.Store) *server {
	s := &server{
		router:       mux.NewRouter(),
		logger:       logrus.New(),
		store:        store,
		sessionStore: sessionStore,
	}

	s.configureRouter()

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.Use(s.setRequestID)
	s.router.Use(s.logRequest)
	s.router.Use(
		handlers.CORS(
			handlers.AllowedOrigins([]string{"http://localhost:3000"}),
			handlers.AllowedMethods([]string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"}),
			handlers.AllowedHeaders([]string{"X-Requested-with", "Content-Type", "Accept", "X-HTTP-Method-Override"}),
			handlers.AllowCredentials(),
		))

	// USER AUTH
	authRouter := s.router.PathPrefix("/authorized").Subrouter()
	authRouter.Use(s.authorizeUser)

	// ADMIN AUTH
	authAdmin := s.router.PathPrefix("/admin").Subrouter()
	authAdmin.Use(s.authorizeAdmin)
	authAdmin.HandleFunc("/roles", s.handleRolesGetAll()).Methods("GET", "OPTIONS")
	authAdmin.HandleFunc("/rolescreate", s.handleRolesCreate()).Methods("POST", "OPTIONS")
	authAdmin.HandleFunc("/rolesadm/{id}", s.handleRolesRemove()).Methods("DELETE", "OPTIONS")

	authAdmin.HandleFunc("/users", s.handleUsersGetAll()).Methods("GET", "OPTIONS")
	authAdmin.HandleFunc("/userfind/{id}", s.handleUserFindById()).Methods("GET", "OPTIONS")
	authAdmin.HandleFunc("/users/{id}", s.handleUsersUpdate()).Methods("PATCH", "OPTIONS")
	authAdmin.HandleFunc("/usersadm/{id}", s.handleUsersRemove()).Methods("DELETE", "OPTIONS")
	authAdmin.HandleFunc("/usersadm", s.handleUsersCreateAdm()).Methods("POST", "OPTIONS")

	//
	s.router.HandleFunc("/login", s.handleLogin()).Methods("POST", "OPTIONS")
}

// s.router.HandleFunc("/userscreate", s.handleUsersCreate()).Methods("POST", "OPTIONS")
// 	s.router.HandleFunc("/roles", s.handleRolesCreate()).Methods("POST", "OPTIONS")
// 	s.router.HandleFunc("/users/{id}", s.handleUsersUpdate()).Methods("PATCH", "OPTIONS")

func (s *server) handleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var credentials Credentials
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user, err := s.store.User().FindByEmail(credentials.Email)
		if err != nil {
			if errors.Is(err, store.ErrRecordNotFound) {
				s.error(w, r, http.StatusUnauthorized, errors.New("invalid email or password"))
			} else {
				s.error(w, r, http.StatusInternalServerError, err)
			}
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.EncryptedPassword), []byte(credentials.Password)); err != nil {
			s.error(w, r, http.StatusUnauthorized, errors.New("invalid email or password"))
			return
		}

		expirationTime := time.Now().Add(time.Minute * 30)
		claims := &Claims{
			RoleID: fmt.Sprint(user.RoleId),
			Email:  user.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			s.error(w, r, http.StatusGone, err)
			return
		}

		http.SetCookie(w,
			&http.Cookie{
				Name:    "token",
				Value:   tokenString,
				Expires: expirationTime,
			},
		)
	}
}

func (s *server) handleUsersCreate() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		u := &users.User{
			Email:    req.Email,
			Password: req.Password,
			RoleId:   3,
		}
		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		u.Sanitize()
		s.respond(w, r, http.StatusCreated, u)
	}
}

func (s *server) handleUsersCreateAdm() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		RoleId   int    `json:"role_id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		tokenStr := cookie.Value

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		if !tkn.Valid {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		logrus.Infof("Hello, %s", claims.Email)

		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		check, err := s.store.User().FindByEmail(claims.Email)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		if check.RoleId != 1 {
			s.error(w, r, http.StatusForbidden, errors.New("only administrators can create users"))
			return
		}

		u := &users.User{
			Email:    req.Email,
			Password: req.Password,
			RoleId:   req.RoleId,
		}

		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		u.Sanitize()

		s.respond(w, r, http.StatusCreated, u)

	}
}

func (s *server) handleUsersGetAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.store.User().GetAll()
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		var userTs []users.UserT
		for _, u := range *user {
			role, err := s.store.Roles().Find(u.RoleId)
			if err != nil {
				s.error(w, r, http.StatusInternalServerError, err)
				return
			}
			ut := &users.UserT{
				Id:                u.Id,
				Email:             u.Email,
				Password:          u.Password,
				EncryptedPassword: u.EncryptedPassword,
				RoleTitle:         role.Title,
			}

			userTs = append(userTs, *ut)
		}

		s.respond(w, r, http.StatusOK, userTs)
	}
}

func (s *server) handleUserFindById() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user, err := s.store.User().Find(id)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		role, err := s.store.Roles().Find(user.RoleId)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		userT := &users.UserT{
			Id:                user.Id,
			Email:             user.Email,
			Password:          user.Password,
			EncryptedPassword: user.EncryptedPassword,
			RoleTitle:         role.Title,
		}

		s.respond(w, r, http.StatusOK, userT)
	}
}

func (s *server) handleUsersUpdate() http.HandlerFunc {
	type request struct {
		Email  string `json:"email"`
		RoleId string `json:"role_title"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}
		vars := mux.Vars(r)
		userId, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		roleId, err := strconv.Atoi(req.RoleId)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u := &users.User{
			Email:  req.Email,
			RoleId: roleId,
		}

		if err := s.store.User().Update(userId, u); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
	}
}

func (s *server) handleUsersRemove() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		tokenStr := cookie.Value

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				s.error(w, r, http.StatusUnauthorized, err)
				return
			}
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		if !tkn.Valid {
			s.error(w, r, http.StatusUnauthorized, err)
			return
		}

		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		if claims.RoleID != "1" {
			s.error(w, r, http.StatusForbidden, errors.New("only administrators can create users"))
			return
		}

		if err := s.store.User().Remove(id); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, nil)

	}
}

func (s *server) handleRolesCreate() http.HandlerFunc {
	type request struct {
		Title string `json:"title"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		role := &roles.Role{
			Title: req.Title,
		}
		if err := s.store.Roles().Create(role); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		s.respond(w, r, http.StatusCreated, role)
	}
}

func (s *server) handleRolesGetAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, err := s.store.Roles().GetAll()
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, role)
	}
}

func (s *server) handleRolesFind() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		role, err := s.store.Roles().Find(id)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, role)
	}
}

func (s *server) handleRolesRemove() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		if err := s.store.Roles().Remove(id); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
}

func (s *server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(ctxKeyRequestID),
		})
		logger.Infof("started %s %s", r.Method, r.RequestURI)

		start := time.Now()
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		logger.Infof(
			"completed with %d %s in %v",
			rw.code,
			http.StatusText(rw.code),
			time.Now().Sub(start),
		)
	})
}

func (s *server) authorizeUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenStr := cookie.Value

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)
	})
}

func (s *server) authorizeAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenStr := cookie.Value

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if claims.RoleID != "1" {
			s.error(w, r, http.StatusForbidden, errors.New("only administrators can create users"))
			return
		}

		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)
	})
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// func CheckLogin(w http.ResponseWriter, r *http.Request) {
// }
