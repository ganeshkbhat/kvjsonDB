package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	// "os"
)

// --- Configuration (Matches server defaults) ---
const (
	API_HOST = "localhost"
	API_PORT = "8888" 
)

// --- Structures (Copied from main.go for consistency) ---
// Command represents the JSON request sent to the server.
type Command struct {
	Op       string                 `json:"op"`
	Key      string                 `json:"key,omitempty"`
	Value    interface{}            `json:"value,omitempty"`
	Term     string                 `json:"term,omitempty"`
	Filename string                 `json:"filename,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	// Note: NewID and Message are omitted as they are typically restricted 
	// or not relevant for the plain API commands.
}

// Response represents the JSON response received from the server.
type Response struct {
	Status   string      `json:"status"`
	Op       string      `json:"op,omitempty"`
	Message  string      `json:"message,omitempty"`
	Key      string      `json:"key,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Results  interface{} `json:"results,omitempty"`
	Data     interface{} `json:"data,omitempty"`
}

// ---------------------------------------------------------------------
// --- API Client Implementation ---
// ---------------------------------------------------------------------

// APIClient holds the connection and facilitates communication.
type APIClient struct {
	conn net.Conn
}

// NewAPIClient connects to the API host and port.
func NewAPIClient(host, port string) (*APIClient, error) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API at %s: %v", addr, err)
	}
	return &APIClient{conn: conn}, nil
}

// Close closes the underlying TCP connection.
func (c *APIClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// executeCommand sends a Command struct and waits for a Response.
func (c *APIClient) executeCommand(cmd Command) (Response, error) {
	// 1. Send Request
	bytes, err := json.Marshal(cmd)
	if err != nil {
		return Response{}, fmt.Errorf("error marshalling command: %v", err)
	}
	// Write the JSON payload followed by a newline delimiter
	_, err = c.conn.Write(append(bytes, '\n'))
	if err != nil {
		return Response{}, fmt.Errorf("error writing to socket: %v", err)
	}

	// 2. Read Response
	reader := bufio.NewReader(c.conn)
	// ReadBytes stops at the first occurrence of the delimiter '\n'
	responseBytes, err := reader.ReadBytes('\n') 
	if err != nil {
		return Response{}, fmt.Errorf("error reading from socket: %v", err)
	}

	// 3. Decode Response
	var resp Response
	if err := json.Unmarshal(responseBytes, &resp); err != nil {
		// Log raw response for debugging if decoding fails
		log.Printf("Failed to unmarshal response: %v, Raw: %s", err, string(responseBytes))
		return Response{}, fmt.Errorf("error unmarshalling response: %v", err)
	}

	return resp, nil
}

// --- Specific API Methods ---

// Set sends a SET command.
func (c *APIClient) Set(key string, value interface{}) (Response, error) {
	cmd := Command{Op: "SET", Key: key, Value: value}
	return c.executeCommand(cmd)
}

// Get sends a GET command.
func (c *APIClient) Get(key string) (Response, error) {
	cmd := Command{Op: "GET", Key: key}
	return c.executeCommand(cmd)
}

// Delete sends a DELETE command.
func (c *APIClient) Delete(key string) (Response, error) {
	cmd := Command{Op: "DELETE", Key: key}
	return c.executeCommand(cmd)
}

// Dump sends a DUMP command.
func (c *APIClient) Dump() (Response, error) {
	cmd := Command{Op: "DUMP"}
	return c.executeCommand(cmd)
}

// ---------------------------------------------------------------------
// --- Example Usage ---
// ---------------------------------------------------------------------

func main() {
	// 1. Establish connection
	client, err := NewAPIClient(API_HOST, API_PORT)
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
	defer client.Close()
	fmt.Printf("Connected to API gateway at %s:%s\n", API_HOST, API_PORT)

	// --- Test 1: SET (key, string value) ---
	setKey := "product:101"
	resp, err := client.Set(setKey, "Keyboard RGB")
	if err != nil { log.Fatal(err) }
	
	fmt.Printf("\n--- SET %s ---\n", setKey)
	if resp.Status == "OK" {
		fmt.Printf("✅ Success: Key %s set.\n", setKey)
	} else {
		fmt.Printf("❌ Error: %s - %s\n", resp.Status, resp.Message)
	}

	// --- Test 2: GET (key) ---
	resp, err = client.Get(setKey)
	if err != nil { log.Fatal(err) }

	fmt.Printf("\n--- GET %s ---\n", setKey)
	if resp.Status == "OK" {
		fmt.Printf("✅ Success: Value: %v\n", resp.Value)
	} else {
		fmt.Printf("❌ Error: %s - %s\n", resp.Status, resp.Message)
	}

	// --- Test 3: SET (key, JSON object value) ---
	jsonValue := map[string]interface{}{"price": 59.99, "stock": 150}
	resp, err = client.Set("inventory:101", jsonValue)
	if err != nil { log.Fatal(err) }
	
	fmt.Printf("\n--- SET inventory:101 ---\n")
	if resp.Status == "OK" {
		fmt.Printf("✅ Success: JSON object set.\n")
	} else {
		fmt.Printf("❌ Error: %s - %s\n", resp.Status, resp.Message)
	}

	// --- Test 4: DUMP all data ---
	resp, err = client.Dump()
	if err != nil { log.Fatal(err) }
	
	fmt.Printf("\n--- DUMP ---\n")
	if resp.Status == "OK" {
		// Pretty print the map received in the Data field
		prettyData, _ := json.MarshalIndent(resp.Data, "", "  ")
		fmt.Println("Store Contents:")
		fmt.Println(string(prettyData))
	} else {
		fmt.Printf("❌ Error: %s - %s\n", resp.Status, resp.Message)
	}
}