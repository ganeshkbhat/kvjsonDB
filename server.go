package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	// "io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Configuration ---
const (
	HOST            = "localhost"
	DEFAULT_PORT    = "9999"
	CERTFILE        = "server.crt"
	KEYFILE         = "server.key"
	CLIENT_CERTFILE = "ca.crt"
	DUMP_FILENAME   = "store_dump.json"
)

// --- Global State ---
var (
	clientIdCounter int
	activeClients   = make(map[interface{}]*ClientConnection)
	clientsMutex    sync.Mutex // Protects activeClients and clientIdCounter
)

// --- Structures ---

// ClientConnection wraps the socket and ID
type ClientConnection struct {
	Socket net.Conn
	ID     interface{} // Can be int or string (after SETID)
}

// Request represents the incoming JSON command
type Request struct {
	Op       string                 `json:"op"`
	Key      string                 `json:"key,omitempty"`
	Value    interface{}            `json:"value,omitempty"` // For SET
	Data     map[string]interface{} `json:"data,omitempty"`  // For LOAD/INIT
	Filename string                 `json:"filename,omitempty"`
	Term     interface{}            `json:"term,omitempty"` // For SEARCH
	Message  string                 `json:"message,omitempty"`
	NewID    interface{}            `json:"newId,omitempty"`
}

// Response represents the outgoing JSON
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

// KeyValueStore handles data locking and operations
type KeyValueStore struct {
	Data map[string]interface{}
	Lock sync.RWMutex // Global lock for the map (Go maps are not safe for concurrent use)
}

var store = KeyValueStore{
	Data: make(map[string]interface{}),
}

// --- Client Management ---

func NewClientConnection(conn net.Conn) *ClientConnection {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	clientIdCounter++
	client := &ClientConnection{
		Socket: conn,
		ID:     clientIdCounter,
	}
	activeClients[client.ID] = client
	return client
}

func (c *ClientConnection) SetClientID(newID interface{}) bool {
	if newID == nil || newID == "" {
		return false
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	// Delete old reference
	delete(activeClients, c.ID)
	// Update ID
	c.ID = newID
	// Add new reference
	activeClients[c.ID] = c
	log.Printf("Client ID updated to: %v", c.ID)
	return true
}

func (c *ClientConnection) WriteJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Println("Error marshaling JSON:", err)
		return
	}
	// Append newline as delimiter
	c.Socket.Write(append(data, '\n'))
}

func (c *ClientConnection) Close() {
	clientsMutex.Lock()
	delete(activeClients, c.ID)
	clientsMutex.Unlock()
	c.Socket.Close()
	log.Printf("Connection closed for Client ID: %v", c.ID)
}

// --- Broadcast Logic ---

func broadcastMessage(senderID interface{}, message string) int {
	timestamp := time.Now().Format(time.RFC3339)
	payload := Response{
		Status:   "BROADCAST",
		SenderId: senderID,
		Message:  message,
		Time:     timestamp,
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	recipients := 0
	for id, client := range activeClients {
		if id != senderID {
			client.WriteJSON(payload)
			recipients++
		}
	}
	log.Printf("[Broadcast] Message from Client %v to %d others.", senderID, recipients)
	return recipients
}

// --- Store Logic ---

func (s *KeyValueStore) LoadData(newData map[string]interface{}) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	for k, v := range newData {
		s.Data[k] = v
	}
}

func (s *KeyValueStore) InitializeData(newData map[string]interface{}) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	s.Data = make(map[string]interface{}) // Reset
	if newData != nil {
		for k, v := range newData {
			s.Data[k] = v
		}
	}
}

func (s *KeyValueStore) DumpToFile(filename string) Response {
	s.Lock.RLock()
	defer s.Lock.RUnlock()

	fileData, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return Response{Status: "ERROR", Op: "DUMPTOFILE", Message: err.Error()}
	}

	err = os.WriteFile(filename, fileData, 0644)
	if err != nil {
		log.Println("Error writing dump file:", err)
		return Response{Status: "ERROR", Op: "DUMPTOFILE", Message: "Failed to write file: " + err.Error()}
	}

	return Response{Status: "OK", Op: "DUMPTOFILE", Message: "Data successfully written to " + filename}
}

// --- Connection Handler ---

func handleConnection(conn net.Conn) {
	// Verify TLS (Go handles the handshake before we get here, but we check verification)
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return
	}

	// Handshake usually happens on first Read/Write, but let's force it to check Auth
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS Handshake failed: %s", err)
		conn.Close()
		return
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		log.Println("Client rejected: Unauthorized certificate.")
		conn.Write([]byte(`{"status":"ERROR","message":"Unauthorized client"}` + "\n"))
		conn.Close()
		return
	}

	client := NewClientConnection(conn)
	defer client.Close()

	log.Printf("(✓) New secure connection. Client ID: %v", client.ID)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		rawMessage := scanner.Bytes()
		if len(rawMessage) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(rawMessage, &req); err != nil {
			client.WriteJSON(Response{Status: "ERROR", Message: "Invalid JSON: " + err.Error()})
			continue
		}

		var resp Response

		switch req.Op {
		case "BROADCAST":
			count := broadcastMessage(client.ID, req.Message)
			resp = Response{
				Status:   "OK",
				Op:       "BROADCAST",
				Message:  fmt.Sprintf("Message sent to %d clients.", count),
				SenderId: client.ID,
			}

		case "SETID":
			if client.SetClientID(req.NewID) {
				resp = Response{Status: "OK", Op: "SETID", Message: fmt.Sprintf("Client ID changed to %v", client.ID)}
			} else {
				resp = Response{Status: "ERROR", Op: "SETID", Message: "Invalid ID provided."}
			}

		case "LOAD", "INIT":
			dataToLoad := req.Data
			source := "inline object"

			if req.Filename != "" {
				fileBytes, err := os.ReadFile(req.Filename)
				if err != nil {
					client.WriteJSON(Response{Status: "ERROR", Op: req.Op, Message: "Failed to load file: " + err.Error()})
					continue
				}
				if err := json.Unmarshal(fileBytes, &dataToLoad); err != nil {
					client.WriteJSON(Response{Status: "ERROR", Op: req.Op, Message: "Invalid JSON in file."})
					continue
				}
				source = "file " + req.Filename
			}

			if req.Op == "LOAD" {
				store.LoadData(dataToLoad)
				resp = Response{Status: "OK", Op: "LOAD", Message: fmt.Sprintf("Data merged from %s.", source)}
			} else {
				store.InitializeData(dataToLoad)
				resp = Response{Status: "OK", Op: "INIT", Message: fmt.Sprintf("Store initialized from %s.", source)}
			}

		case "SEARCH", "SEARCHKEY":
			term := strings.ToLower(fmt.Sprintf("%v", req.Term))
			results := make(map[string]interface{})

			store.Lock.RLock()
			for k, v := range store.Data {
				lowerKey := strings.ToLower(k)
				match := false
				if req.Op == "SEARCHKEY" {
					if strings.Contains(lowerKey, term) {
						match = true
					}
				} else {
					// SEARCH (Value and Key)
					jsonVal, _ := json.Marshal(v)
					if strings.Contains(lowerKey, term) || strings.Contains(strings.ToLower(string(jsonVal)), term) {
						match = true
					}
				}

				if match {
					results[k] = v
				}
			}
			store.Lock.RUnlock()
			resp = Response{Status: "OK", Op: req.Op, Results: results}

		case "DUMPTOFILE":
			resp = store.DumpToFile(DUMP_FILENAME)

		case "DUMP":
			store.Lock.RLock()
			// Copy map to avoid race conditions during serialization after unlock
			copyData := make(map[string]interface{})
			for k, v := range store.Data {
				copyData[k] = v
			}
			store.Lock.RUnlock()
			resp = Response{Status: "OK", Op: "DUMP", Data: copyData}

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
			_, exists := store.Data[req.Key]
			if exists {
				delete(store.Data, req.Key)
				store.Lock.Unlock()
				resp = Response{Status: "OK", Op: "DELETE", Key: req.Key}
			} else {
				store.Lock.Unlock()
				resp = Response{Status: "NOT_FOUND", Op: "DELETE", Key: req.Key}
			}

		default:
			resp = Response{Status: "ERROR", Message: "Unknown operation"}
		}

		client.WriteJSON(resp)
	}
}

// --- Main Server Start ---

func main() {
	port := DEFAULT_PORT
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// Load CA to verify clients
	caCert, err := os.ReadFile(CLIENT_CERTFILE)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load Server Cert/Key
	cert, err := tls.LoadX509KeyPair(CERTFILE, KEYFILE)
	if err != nil {
		log.Fatal(err)
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

	log.Printf("Secure Key-Value TCP Server listening on %s:%s", HOST, port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn)
	}
}