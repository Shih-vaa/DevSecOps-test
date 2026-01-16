package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	_ "github.com/mattn/go-sqlite3" // Example vulnerable/outdated dependency
	_ "crypto/md5"                  // unused import
)

var (
	// Hardcoded credentials (Bad Practice)
	dbUser     = "admin"
	dbPassword = "admin123"
	apiKey     = "HARDCODED-API-KEY-123456"
)

type CartItem struct {
	ID       int    `json:"id"`
	Product  string `json:"product"`
	Quantity int    `json:"quantity"`
	UserID   int    `json:"user_id"`
}

var db *sql.DB

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

// SQL Injection vulnerability + Insecure Deserialization
func addToCart(w http.ResponseWriter, r *http.Request) {
	var item CartItem
	// Insecure deserialization: blindly decoding user input
	json.NewDecoder(r.Body).Decode(&item)

	// SQL Injection vulnerability: no parameterized queries
	query := fmt.Sprintf("INSERT INTO cart (product, quantity, user_id) VALUES ('%s', %d, %d)",
		item.Product, item.Quantity, item.UserID)
	_, err := db.Exec(query)
	if err != nil {
		// Insufficient logging (not recording user, IP, etc.)
		log.Println("Error inserting into cart")
	}

	fmt.Fprintf(w, "Item added: %s", item.Product)
}

// Broken Access Control + XSS
func viewCart(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user") // user controls the ID

	// No access control: any user can view any cart by passing another user ID
	rows, _ := db.Query("SELECT id, product, quantity, user_id FROM cart WHERE user_id=" + userID)

	var items []CartItem
	for rows.Next() {
		var it CartItem
		rows.Scan(&it.ID, &it.Product, &it.Quantity, &it.UserID)
		items = append(items, it)
	}

	// XSS: reflecting user-controlled input directly
	tmpl := template.Must(template.New("view").Parse(`
		<h1>Cart for User {{.User}}</h1>
		<p>Showing results for user: {{.User}}</p>
		<ul>
			{{range .Items}}
				<li>{{.Product}} (Qty: {{.Quantity}})</li>
			{{end}}
		</ul>
	`))
	tmpl.Execute(w, map[string]interface{}{
		"User":  userID,
		"Items": items,
	})
}

// Broken Access Control: no authentication for admin panel
func adminPanel(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id, product, quantity, user_id FROM cart")

	fmt.Fprintln(w, "<h1>Admin Panel</h1><ul>")
	for rows.Next() {
		var it CartItem
		rows.Scan(&it.ID, &it.Product, &it.Quantity, &it.UserID)
		fmt.Fprintf(w, "<li>User %d: %s (x%d)</li>", it.UserID, it.Product, it.Quantity)
	}
	fmt.Fprintln(w, "</ul>")
}

// Invalid Redirects/Forwards
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// No validation -> attacker can redirect to malicious site
	http.Redirect(w, r, target, http.StatusFound)
}