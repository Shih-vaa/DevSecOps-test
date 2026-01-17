package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

var (
	dbUser     = os.Getenv("DB_USER")
	dbPassword = os.Getenv("DB_PASSWORD")
	apiKey     = os.Getenv("API_KEY")
)

type CartItem struct {
	ID       int    `json:"id"`
	Product  string `json:"product"`
	Quantity int    `json:"quantity"`
	UserID   int    `json:"user_id"`
}

var db *sql.DB

func is_authenticated(r *http.Request) bool {
	// Simple authentication check using a request header
	return r.Header.Get("X-Auth-Token") != ""
}

func is_admin(r *http.Request) bool {
	// Simple admin check using a request header
	return r.Header.Get("X-Admin-Token") != ""
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./cart.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.HandleFunc("/add", addToCart)
	http.HandleFunc("/view", viewCart)
	http.HandleFunc("/admin", adminPanel)
	http.HandleFunc("/redirect", redirectHandler)

	fmt.Println("Cart service running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func addToCart(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var item CartItem
	err := json.NewDecoder(r.Body).Decode(&item)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Use parameterized queries to prevent SQL injection
	query := "INSERT INTO cart (product, quantity, user_id) VALUES (?, ?, ?)"
	_, err = db.Exec(query, item.Product, item.Quantity, item.UserID)
	if err != nil {
		log.Printf("Error inserting into cart: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Item added: %s", item.Product)
}

func viewCart(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID := r.URL.Query().Get("user")
	if userID == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Use parameterized queries to prevent SQL injection
	query := "SELECT id, product, quantity, user_id FROM cart WHERE user_id = ?"
	rows, err := db.Query(query, userID)
	if err != nil {
		log.Printf("Error querying cart: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []CartItem
	for rows.Next() {
		var it CartItem
		err = rows.Scan(&it.ID, &it.Product, &it.Quantity, &it.UserID)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		items = append(items, it)
	}

	tmpl := template.Must(template.New("view").Parse(`
		Cart for User {{.User}}
		Showing results for user: {{.User}}
		
			{{range .Items}}
				{{.Product}} (Qty: {{.Quantity}})
			{{end}}
		
	`))
	tmpl.Execute(w, map[string]interface{}{
		"User":  template.HTML(userID), // Escape user-controlled input
		"Items": items,
	})
}

func adminPanel(w http.ResponseWriter, r *http.Request) {
	if !is_admin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Use parameterized queries to prevent SQL injection
	rows, err := db.Query("SELECT id, product, quantity, user_id FROM cart")
	if err != nil {
		log.Printf("Error querying cart: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	fmt.Fprintln(w, "Admin Panel")
	for rows.Next() {
		var it CartItem
		err = rows.Scan(&it.ID, &it.Product, &it.Quantity, &it.UserID)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "User %d: %s (x%d)", it.UserID, it.Product, it.Quantity)
	}
	fmt.Fprintln(w, "")
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate redirect target using an allowlist
	allowlist := []string{"http://example.com", "https://example.com"}
	for _, allowed := range allowlist {
		if target == allowed {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}

	http.Error(w, "Forbidden", http.StatusForbidden)
}