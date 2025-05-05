package client

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/jayjaytrn/gophkeeper/internal/types"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

var (
	baseURL      = "http://localhost:8080"
	cookieJar, _ = cookiejar.New(nil)
	httpClient   = &http.Client{
		Jar: cookieJar,
	}
)

const cookieFile = "auth.cookie"

// init loads cookies from the file to persist session between runs.
func init() {
	loadCookies()
}

// Register registers a new user with login and password.
func Register() {
	var login, password string
	fmt.Print("Login: ")
	fmt.Scan(&login)
	fmt.Print("Password: ")
	fmt.Scan(&password)

	payload := map[string]string{
		"login":    login,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	resp, err := httpClient.Post(baseURL+"/api/register", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Registration error:", err)
		return
	}
	defer resp.Body.Close()

	saveCookies(resp)

	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to register: %s\n", string(msg))
		return
	}

	fmt.Println("Registered successfully")
}

// Login authenticates a user and saves cookies.
func Login() {
	var login, password string
	fmt.Print("Login: ")
	fmt.Scan(&login)
	fmt.Print("Password: ")
	fmt.Scan(&password)

	payload := map[string]string{
		"login":    login,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	resp, err := httpClient.Post(baseURL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Login error:", err)
		return
	}
	defer resp.Body.Close()

	saveCookies(resp)

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to login: %s\n", string(msg))
		return
	}

	fmt.Println("Logged in successfully")
}

// SaveData sends a new sensitive record to the server.
func SaveData() {
	var req types.ClientSaveRequest

	username := prompt("Username to store (Enter to skip): ")
	if username != "" {
		password := prompt("Password to store: ")
		meta := prompt("Metadata for credentials: ")
		req.Credentials = types.Credentials{
			Username: username,
			Password: password,
			Metadata: types.Metadata{"info": meta},
		}
	}

	textNote := prompt("Text note (Enter to skip): ")
	if textNote != "" {
		meta := prompt("Metadata for text: ")
		req.TextData = types.TextData{
			TextData: textNote,
			Metadata: types.Metadata{"info": meta},
		}
	}

	card := prompt("Card info (Enter to skip): ")
	if card != "" {
		meta := prompt("Metadata for card: ")
		req.CardDetails = types.CardDetails{
			CardDetails: card,
			Metadata:    types.Metadata{"info": meta},
		}
	}

	bin := prompt("Binary data (as string, Enter to skip): ")
	if bin != "" {
		meta := prompt("Metadata for binary: ")
		req.BinaryData = types.BinaryData{
			BinaryData: []byte(bin),
			Metadata:   types.Metadata{"info": meta},
		}
	}

	if req.Credentials.Username == "" &&
		req.TextData.TextData == "" &&
		len(req.BinaryData.BinaryData) == 0 &&
		req.CardDetails.CardDetails == "" {
		fmt.Println("Nothing to save.")
		return
	}

	body, _ := json.Marshal(req)

	resp, err := httpClient.Post(baseURL+"/data", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Unauthorized: please login first.")
		return
	}

	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to save data: %s\n", string(msg))
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Failed to parse server response:", err)
		return
	}

	fmt.Printf("Data saved. ID: %v\n", result["data_id"])
}

// GetDataByID retrieves and prints sensitive data by ID.
func GetDataByID(id string) {
	url := fmt.Sprintf("%s/data/%s", baseURL, id)
	resp, err := httpClient.Get(url)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to fetch data by ID: %s\n", string(msg))
		return
	}

	var entry types.SensitiveData
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		fmt.Println("Failed to decode response:", err)
		return
	}

	fmt.Printf("Data ID: %v\n", entry.DataID)
	fmt.Printf("Credentials: %+v\n", entry.Credentials)
	fmt.Printf("Text Data: %+v\n", entry.TextData)
	fmt.Printf("Card Details: %+v\n", entry.CardDetails)
	if len(entry.BinaryData.BinaryData) > 0 {
		fmt.Println("Binary Data:")
		fmt.Printf("  Bytes: %s\n", string(entry.BinaryData.BinaryData))
		fmt.Printf("  Metadata: %+v\n", entry.BinaryData.Metadata)
	}
}

// ListData retrieves all stored data for the user.
func ListData() {
	resp, err := httpClient.Get(baseURL + "/data")
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to fetch data: %s\n", string(msg))
		return
	}

	var records []types.SensitiveData
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		fmt.Println("Failed to decode response:", err)
		return
	}

	if len(records) == 0 {
		fmt.Println("No data found.")
		return
	}

	for _, record := range records {
		fmt.Printf("\nData ID: %d\n", record.DataID)
		fmt.Printf("Credentials: %+v\n", record.Credentials)
		fmt.Printf("Text Data: %+v\n", record.TextData)
		fmt.Printf("Card Details: %+v\n", record.CardDetails)
		fmt.Printf("Binary Data: %s\n", string(record.BinaryData.BinaryData))
	}
}

// loadCookies reads cookies from file into jar.
func loadCookies() {
	u, _ := url.Parse(baseURL)

	file, err := os.Open(cookieFile)
	if err != nil {
		return
	}
	defer file.Close()

	var cookies []*http.Cookie
	if err := gob.NewDecoder(file).Decode(&cookies); err != nil {
		return
	}

	cookieJar.SetCookies(u, cookies)
}

// saveCookies persists cookies to file.
func saveCookies(resp *http.Response) {
	u, _ := url.Parse(baseURL)

	file, err := os.Create(cookieFile)
	if err != nil {
		return
	}
	defer file.Close()

	cookies := httpClient.Jar.Cookies(u)
	_ = gob.NewEncoder(file).Encode(cookies)
}

// prompt reads user input from the console with label.
func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}
