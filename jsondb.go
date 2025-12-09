package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Configuration Constants ---
const (
	HOST          = "127.0.0.1"
	DEFAULT_PORT  = "9999"
	SERVER_CERT   = "server.crt"
	SERVER_KEY    = "server.key"
	CLIENT_CERT   = "client.crt"
	CLIENT_KEY    = "client.key"
	CA_CERT       = "ca.crt" // Shared CA for mutual trust
	DUMP_FILENAME = "store_dump.json"
)

// --- Shared Structures ---

// Request/Command (Client sends this)
type Request struct {
	Op       string                 `json:"op"`
	Key      string                 `json:"key,omitempty"`
	Value    interface{}            `json:"value,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	Filename string                 `json:"filename,omitempty"`
	Term     interface{}            `json:"term,omitempty"`
	Message  string                 `json:"message,omitempty"`
	NewID    interface{}            `json:"newId,omitempty"`
}

// Response (Server sends this)
type Response struct {
	Status   string      `json:"status"`
	Op       string      `json:"op,omitempty"`
	Message  string      `json:"message,omitempty"`
	Key      string      `json:"key,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	SenderId interface{} `json:"senderId,omitempty"`
	Results  interface{} `json:"results,omitempty"`
	Data     interface{} `json:"data,omitempty"`
	Time     string      `json:"timestamp,omitempty"`
}

// --- Server Global State ---
var (
	clientIdCounter int
	activeClients   = make(map[interface{}]*ClientConnection)
	clientsMutex    sync.Mutex
	store           = KeyValueStore{Data: make(map[string]interface{})}
)

type ClientConnection struct {
	Socket net.Conn
	ID     interface{}
}

type KeyValueStore struct {
	Data map[string]interface{}
	Lock sync.RWMutex
}

// --- Main Entry Point ---

func main() {
	// Custom flag usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -s <db|shell> [port]\n", os.Args[0])
		flag.PrintDefaults()
	}

	modePtr := flag.String("s", "", "Mode to run: 'db' or 'shell'")
	flag.Parse()

	// Get port from remaining args or default
	port := DEFAULT_PORT
	if len(flag.Args()) > 0 {
		port = flag.Args()[0]
	}

	switch *modePtr {
	case "db":
		runServer(port)
	case "shell":
		runShell(port)
	default:
		fmt.Println("Error: You must specify a mode using -s.")
		flag.Usage()
		os.Exit(1)
	}
}

// ==========================================
//               SERVER LOGIC
// ==========================================

func runServer(port string) {
	// Load CA to verify clients
	caCert, err := os.ReadFile(CA_CERT)
	if err != nil {
		log.Fatalf("Error reading CA cert (%s): %v", CA_CERT, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load Server Cert/Key
	cert, err := tls.LoadX509KeyPair(SERVER_CERT, SERVER_KEY)
	if err != nil {
		log.Fatalf("Error loading server keypair: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
	}

	listener, err := tls.Listen("tcp", HOST+":"+port, config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("✅ Secure Key-Value DB Server running on %s:%s", HOST, port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleServerConnection(conn)
	}
}

func handleServerConnection(conn net.Conn) {
	defer conn.Close()

	// TLS handshake verification
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS Handshake failed: %s", err)
			return
		}
	}

	// Register Client
	clientsMutex.Lock()
	clientIdCounter++
	client := &ClientConnection{Socket: conn, ID: clientIdCounter}
	activeClients[client.ID] = client
	clientsMutex.Unlock()

	defer func() {
		clientsMutex.Lock()
		delete(activeClients, client.ID)
		clientsMutex.Unlock()
		log.Printf("Connection closed for Client ID: %v", client.ID)
	}()

	log.Printf("🔗 New connection. Client ID: %v", client.ID)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		rawMessage := scanner.Bytes()
		var req Request
		if err := json.Unmarshal(rawMessage, &req); err != nil {
			writeJSON(conn, Response{Status: "ERROR", Message: "Invalid JSON"})
			continue
		}

		handleRequest(client, req)
	}
}

func handleRequest(client *ClientConnection, req Request) {
	var resp Response

	switch req.Op {
	case "BROADCAST":
		count := 0
		clientsMutex.Lock()
		for id, c := range activeClients {
			if id != client.ID {
				msg := Response{Status: "BROADCAST", SenderId: client.ID, Message: req.Message, Time: time.Now().Format(time.RFC3339)}
				writeJSON(c.Socket, msg)
				count++
			}
		}
		clientsMutex.Unlock()
		resp = Response{Status: "OK", Op: "BROADCAST", Message: fmt.Sprintf("Sent to %d clients.", count)}

	case "SETID":
		clientsMutex.Lock()
		delete(activeClients, client.ID)
		client.ID = req.NewID
		activeClients[client.ID] = client
		clientsMutex.Unlock()
		resp = Response{Status: "OK", Op: "SETID", Message: fmt.Sprintf("ID updated to %v", client.ID)}

	case "SET":
		store.Lock.Lock()
		store.Data[req.Key] = req.Value
		store.Lock.Unlock()
		resp = Response{Status: "OK", Op: "SET", Key: req.Key}

	case "GET":
		store.Lock.RLock()
		val, exists := store.Data[req.Key]
		store.Lock.RUnlock()
		if exists {
			resp = Response{Status: "OK", Op: "GET", Key: req.Key, Value: val}
		} else {
			resp = Response{Status: "NOT_FOUND", Op: "GET", Key: req.Key}
		}

	case "DELETE":
		store.Lock.Lock()
		delete(store.Data, req.Key)
		store.Lock.Unlock()
		resp = Response{Status: "OK", Op: "DELETE", Key: req.Key}

	case "DUMP":
		store.Lock.RLock()
		copyData := make(map[string]interface{})
		for k, v := range store.Data {
			copyData[k] = v
		}
		store.Lock.RUnlock()
		resp = Response{Status: "OK", Op: "DUMP", Data: copyData}

	case "DUMPTOFILE":
		store.Lock.RLock()
		fileData, _ := json.MarshalIndent(store.Data, "", "  ")
		store.Lock.RUnlock()
		err := os.WriteFile(DUMP_FILENAME, fileData, 0644)
		if err != nil {
			resp = Response{Status: "ERROR", Op: "DUMPTOFILE", Message: err.Error()}
		} else {
			resp = Response{Status: "OK", Op: "DUMPTOFILE", Message: "Saved to " + DUMP_FILENAME}
		}

	case "SEARCH", "SEARCHKEY":
		term := strings.ToLower(fmt.Sprintf("%v", req.Term))
		results := make(map[string]interface{})
		store.Lock.RLock()
		for k, v := range store.Data {
			lowerKey := strings.ToLower(k)
			match := false
			if strings.Contains(lowerKey, term) {
				match = true
			} else if req.Op == "SEARCH" {
				jsonVal, _ := json.Marshal(v)
				if strings.Contains(strings.ToLower(string(jsonVal)), term) {
					match = true
				}
			}
			if match {
				results[k] = v
			}
		}
		store.Lock.RUnlock()
		resp = Response{Status: "OK", Op: req.Op, Results: results}

	default:
		resp = Response{Status: "ERROR", Message: "Unknown operation"}
	}

	writeJSON(client.Socket, resp)
}

func writeJSON(conn net.Conn, v interface{}) {
	data, _ := json.Marshal(v)
	conn.Write(append(data, '\n'))
}

// ==========================================
//               CLIENT (SHELL) LOGIC
// ==========================================

func runShell(port string) {
	// Load CA
	caCert, err := os.ReadFile(CA_CERT)
	if err != nil {
		log.Fatalf("Error reading CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load Client Certs
	cert, err := tls.LoadX509KeyPair(CLIENT_CERT, CLIENT_KEY)
	if err != nil {
		log.Fatalf("Error reading client certs: %v", err)
	}

	config := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", HOST+":"+port, config)
	if err != nil {
		log.Fatalf("Connection Setup Error: %v", err)
	}
	defer conn.Close()

	fmt.Printf("\n Connected to DB Shell at %s:%s\n", HOST, port)

	// Async Reader
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			text := scanner.Text()
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(text), &resp); err == nil {
				if status, ok := resp["status"].(string); ok && status == "BROADCAST" {
					fmt.Printf("\n📢 [Client %v]: %v\njsondb@%s:%s> ", resp["senderId"], resp["message"], HOST, port)
				} else {
					pretty, _ := json.MarshalIndent(resp, "", "  ")
					fmt.Printf("<- %s\njsondb@%s:%s> ", string(pretty), HOST, port)
				}
			} else {
				fmt.Printf("\n<- %s\njsondb@%s:%s> ", text, HOST, port)
			}
		}
		fmt.Println("\nDisconnected.")
		os.Exit(0)
	}()

	// Input Loop
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("jsondb@%s:%s> ", HOST, port)
	for scanner.Scan() {
		line := scanner.Text()
		cmd, err := parseShellInput(line)
		if err != nil {
			if err.Error() != "empty" {
				fmt.Println("Error:", err)
			}
			fmt.Print("jsondb@%s:%s> ", HOST, port)
			continue
		}
		if cmd.Op == "EXIT" {
			break
		}
		if cmd.Op == "HELP" {
			printHelp()
			fmt.Print("jsondb@%s:%s> ", HOST, port)
			continue
		}

		writeJSON(conn, cmd)
	}
}

func parseShellInput(input string) (Request, error) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return Request{}, fmt.Errorf("empty")
	}
	op := strings.ToUpper(parts[0])

	switch op {
	case "EXIT", "HELP", "DUMP", "DUMPTOFILE":
		return Request{Op: op}, nil
	case "BROADCAST":
		if len(parts) < 2 {
			return Request{}, fmt.Errorf("missing message")
		}
		return Request{Op: op, Message: strings.Join(parts[1:], " ")}, nil
	case "SETID":
		if len(parts) < 2 {
			return Request{}, fmt.Errorf("missing ID")
		}
		return Request{Op: op, NewID: parts[1]}, nil
	case "SEARCH", "SEARCHKEY":
		if len(parts) < 2 {
			return Request{}, fmt.Errorf("missing term")
		}
		return Request{Op: op, Term: parts[1]}, nil
	case "GET", "DELETE":
		if len(parts) < 2 {
			return Request{}, fmt.Errorf("missing key")
		}
		return Request{Op: op, Key: parts[1]}, nil
	case "SET":
		if len(parts) < 3 {
			return Request{}, fmt.Errorf("usage: SET <key> <value>")
		}
		valStr := strings.Join(parts[2:], " ")
		var val interface{}
		// Try parsing as JSON, fallback to string
		if err := json.Unmarshal([]byte(valStr), &val); err != nil {
			if num, err := strconv.ParseFloat(valStr, 64); err == nil {
				val = num
			} else {
				val = valStr
			}
		}
		return Request{Op: op, Key: parts[1], Value: val}, nil
	default:
		return Request{}, fmt.Errorf("unknown command")
	}
}

func printHelp() {
	fmt.Println("Commands: SET, GET, DELETE, SEARCH, SEARCHKEY, BROADCAST, DUMP, DUMPTOFILE, SETID, EXIT")
}