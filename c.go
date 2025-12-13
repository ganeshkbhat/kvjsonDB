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
	"strings"
	"sync"
	"time"
)

// --- Configuration Variables (Parsed by 'flag') ---
var (
	// Server/Network
	mode     *string
	host     *string
	port     *string
	// Security (mTLS)
	certFile    *string
	keyFile     *string
	clientCA    *string
	// Data Persistence
	dumpFile        *string
	securityDumpFile *string // Placeholder for future use
	loadFile        *string
	dumpIntervalStr *string
	logFile         *string
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

// --- Periodic Dump Logic ---

func startPeriodicDump(interval time.Duration) {
	if interval <= 0 {
		log.Println("Periodic dumping disabled.")
		return
	}

	log.Printf("Starting periodic dump every %s to %s", interval, *dumpFile)

	ticker := time.NewTicker(interval)
	// Start with a small delay for cleaner logs
	time.AfterFunc(1*time.Second, func() {
		go func() {
			for {
				select {
				case <-ticker.C:
					log.Printf("Performing scheduled dump to %s...", *dumpFile)
					resp := store.DumpToFile(*dumpFile)
					if resp.Status != "OK" {
						log.Printf("Scheduled dump FAILED: %s", resp.Message)
					} else {
						log.Println("Scheduled dump successful.")
					}
				}
			}
		}()
	})
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
			resp = store.DumpToFile(*dumpFile)

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

// --- Initialization and Main Server Start ---

func setupFlags() {
	// Server/Network
	mode = flag.String("mode", "db", "Mode: Defines the execution type (must be 'db' for server).")
	mode = flag.String("s", *mode, "Mode: Defines the execution type (short form).")
	host = flag.String("host", "localhost", "Host: The interface the server listens on.")
	host = flag.String("h", *host, "Host: The interface the server listens on (short form).")
	port = flag.String("port", "9999", "Port: The TCP port the server listens on.")
	port = flag.String("p", *port, "Port: The TCP port the server listens on (short form).")

	// Security (mTLS)
	certFile = flag.String("cert", "server.crt", "Server Certificate Path.")
	certFile = flag.String("c", *certFile, "Server Certificate Path (short form).")
	keyFile = flag.String("key", "server.key", "Server Private Key Path.")
	keyFile = flag.String("k", *keyFile, "Server Private Key Path (short form).")
	clientCA = flag.String("ca-cert", "ca.crt", "Root CA Certificate Path to verify clients.")
	clientCA = flag.String("ca", *clientCA, "Root CA Certificate Path to verify clients (short form).")

	// Data Persistence
	dumpFile = flag.String("dump-file", "store_dump.json", "Data Dump File: Filename for persistence of the main data store.")
	dumpFile = flag.String("df", *dumpFile, "Data Dump File (short form).")
	securityDumpFile = flag.String("security-dump-file", "security_db_dump.json", "Security Dump File: Filename for persistence of Users/Groups/ACLs.")
	securityDumpFile = flag.String("sdf", *securityDumpFile, "Security Dump File (short form).")
	// The loadFile default is handled after flag.Parse()
	loadFile = flag.String("load", "", "Load File: Initial file to load data from on startup.")
	loadFile = flag.String("l", *loadFile, "Load File (short form).")
	dumpIntervalStr = flag.String("dump-time", "30m", "Periodic Dump Interval: Duration for automatically saving the store (e.g., 5s, 1m, 30m). Set to 0s to disable.")
	dumpIntervalStr = flag.String("dt", *dumpIntervalStr, "Periodic Dump Interval (short form).")

	// Logging
	logFile = flag.String("log", "server.log", "Log File: Path to the server log file. Use \"\" to disable file logging.")

	flag.Parse()
}

func setupLogging() {
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening log file: %v", err)
		}
		log.SetOutput(f)
	}
	// Log flags being used
	log.Printf("Starting server with configuration:")
	log.Printf("  Mode: %s", *mode)
	log.Printf("  Host: %s, Port: %s", *host, *port)
	log.Printf("  Cert: %s, Key: %s, CA: %s", *certFile, *keyFile, *clientCA)
	log.Printf("  Dump File: %s, Load File: %s", *dumpFile, *loadFile)
	log.Printf("  Dump Time: %s, Log File: %s", *dumpIntervalStr, *logFile)
}

func loadInitialData() {
	// If loadFile is still empty (meaning user didn't specify -l/--load),
	// use the dumpFile value as the default.
	if *loadFile == "" {
		*loadFile = *dumpFile
	}

	if *loadFile != "" {
		log.Printf("Attempting to load initial data from: %s", *loadFile)
		fileBytes, err := os.ReadFile(*loadFile)
		if err == nil {
			var initialData map[string]interface{}
			if err := json.Unmarshal(fileBytes, &initialData); err == nil {
				store.InitializeData(initialData)
				log.Printf("Successfully initialized store with data from %s.", *loadFile)
				return
			}
			log.Printf("Warning: Failed to parse JSON from %s: %v", *loadFile, err)
		} else if !os.IsNotExist(err) {
			log.Printf("Warning: Failed to read file %s: %v", *loadFile, err)
		} else {
			log.Printf("Info: Initial load file %s does not exist, starting with empty store.", *loadFile)
		}
	}
}

func main() {
	setupFlags()
	setupLogging()

	if *mode != "db" {
		log.Fatalf("Invalid mode '%s'. Server must run in 'db' mode.", *mode)
	}

	// 1. Load Initial Data
	loadInitialData()

	// 2. Start Periodic Dump
	dumpDuration, err := time.ParseDuration(*dumpIntervalStr)
	if err != nil {
		log.Fatalf("Invalid dump-time format: %v", err)
	}
	startPeriodicDump(dumpDuration)


	// 3. Load CA to verify clients
	caCert, err := os.ReadFile(*clientCA)
	if err != nil {
		log.Fatalf("Error reading client CA cert %s: %v", *clientCA, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 4. Load Server Cert/Key
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Error loading server key pair %s/%s: %v", *certFile, *keyFile, err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
	}

	listener, err := tls.Listen("tcp", *host+":"+*port, config)
	if err != nil {
		log.Fatalf("Listener error: %v", err)
	}
	defer listener.Close()

	log.Printf("Secure Key-Value TCP Server listening on %s:%s", *host, *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn)
	}
}