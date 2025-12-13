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
	// Server/Network (Short flags: -h, -p)
	host *string
	port *string
	// Security (mTLS) (Short flags: -c, -k, -ca)
	certFile *string
	keyFile  *string
	clientCA *string
	// Data Persistence (Short flag: -dt)
	dumpFile        *string
	dumpIntervalStr *string
)

// --- Global State ---
var (
	// clientIdCounter tracks simple sequential ID for new connections
	clientIdCounter int 
	// activeClients now uses string ID for the client identifier
	activeClients   = make(map[string]*ClientConnection) 
	clientsMutex    sync.Mutex // Protects activeClients and clientIdCounter
)

// --- Structures ---

// ClientConnection wraps the socket and ID
type ClientConnection struct {
	Socket net.Conn
	ID     string // ID is now a formatted string (id:ip:port)
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
	SenderId interface{} `json:"senderId,omitempty"` // Kept as interface{} for compatibility but will hold a string
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
    
    // EXTRACT IP AND PORT
	remoteAddr := conn.RemoteAddr().String()
    host, port, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        log.Printf("Error splitting host/port for %s: %v. Using address directly.", remoteAddr, err)
        host = remoteAddr
        port = "unknown"
    }

	// Format the new client ID string
	newID := fmt.Sprintf("%d:%s:%s", clientIdCounter, host, port)

	client := &ClientConnection{
		Socket: conn,
		ID:     newID,
	}
	// Use the formatted string ID as the map key
	activeClients[client.ID] = client 
    
    // Server logs the connection
	log.Printf("Client %s: CONNECTED", client.ID) 
	return client
}

func (c *ClientConnection) SetClientID(newID interface{}) bool {
	idStr, ok := newID.(string)
	if !ok || idStr == "" {
		return false
	}
    
    // OPTIONAL: Prepend the existing network address to the user-defined ID
    // Find the network part of the current ID (e.g., ":127.0.0.1:55000")
    parts := strings.Split(c.ID, ":")
    networkSuffix := ""
    if len(parts) >= 3 {
        networkSuffix = fmt.Sprintf(":%s:%s", parts[len(parts)-2], parts[len(parts)-1])
    }

    finalNewID := idStr + networkSuffix

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	// Delete old reference (using the old formatted ID string)
	delete(activeClients, c.ID)
    
	// Update ID
	c.ID = finalNewID
    
	// Add new reference (using the new formatted ID string)
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
	// Use the formatted string ID as the map key
	delete(activeClients, c.ID) 
	clientsMutex.Unlock()
	// Log client disconnection
	log.Printf("Client %v: DISCONNECT", c.ID)
	c.Socket.Close()
}

// --- Broadcast Logic (No Changes) ---

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
	// Map key is now guaranteed to be string
	senderIDStr, _ := senderID.(string) 

	for id, client := range activeClients {
		if id != senderIDStr {
			client.WriteJSON(payload)
			recipients++
		}
	}
	log.Printf("[Broadcast] Message from Client %v to %d others.", senderID, recipients)
	return recipients
}

// --- Store Logic (No Changes) ---

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

// --- Periodic Dump Logic (No Changes) ---

func startPeriodicDump() {
	// Parse the string duration from the flag
	interval, err := time.ParseDuration(*dumpIntervalStr)
	if err != nil {
		log.Fatalf("Invalid dump-time format '%s': %v", *dumpIntervalStr, err)
	}

	if interval <= 0 {
		log.Println("Periodic dumping disabled.")
		return
	}

	log.Printf("Starting periodic dump every %s to %s", interval, *dumpFile)

	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				log.Printf("Scheduled dump triggered.")
				// Use the dumpFile pointer value
				resp := store.DumpToFile(*dumpFile) 
				if resp.Status != "OK" {
					log.Printf("Scheduled dump FAILED: %s", resp.Message)
				} else {
					log.Println("Scheduled dump successful.")
				}
			}
		}
	}()
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

    // NewClientConnection now logs the connection and sets the full ID string
	client := NewClientConnection(conn) 
	defer client.Close()

    // NEW: Send initial status message to client containing their full ID
    initialStatus := Response{
        Status: "STATUS",
        Op: "CONNECTED",
        Message: "Successfully connected and authenticated.",
        SenderId: client.ID,
    }
    client.WriteJSON(initialStatus)

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
			count := broadcastMessage(client.ID, req.Message) // client.ID is the string ID
			resp = Response{
				Status:   "OK",
				Op:       "BROADCAST",
				Message:  fmt.Sprintf("Message sent to %d clients.", count),
				SenderId: client.ID,
			}
		case "SETID":
            // Note: SETID expects a string ID but will append the network address if successful
			if client.SetClientID(req.NewID) { 
				resp = Response{Status: "OK", Op: "SETID", Message: fmt.Sprintf("Client ID changed to %v", client.ID)}
			} else {
				resp = Response{Status: "ERROR", Op: "SETID", Message: "Invalid ID provided."}
			}

		case "LOAD", "INIT":
            // ... (Load/Init logic remains the same) ...
            
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
            // ... (Search logic remains the same) ...
			term := strings.ToLower(fmt.Sprintf("%v", req.Term)) 
			opType := "SEARCH"
			if req.Op == "SEARCHKEY" {
				opType = "SEARCHKEY"
			}
			log.Printf("Client %v: %s term='%v'", client.ID, opType, req.Term)

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
		
		// --- Blob Operations (Added Logged Stubs) ---
		case "PUTBLOB":
			log.Printf("Client %v: PUTBLOB key='%s' (unimplemented)", client.ID, req.Key)
			resp = Response{Status: "ERROR", Op: "PUTBLOB", Message: "Operation not implemented"}

		case "DELETEBLOB":
			log.Printf("Client %v: DELETEBLOB key='%s' (unimplemented)", client.ID, req.Key)
			resp = Response{Status: "ERROR", Op: "DELETEBLOB", Message: "Operation not implemented"}

		case "GETBLOB":
			log.Printf("Client %v: GETBLOB key='%s' (unimplemented)", client.ID, req.Key)
			resp = Response{Status: "ERROR", Op: "GETBLOB", Message: "Operation not implemented"}
		// ---------------------------------------------
		
		case "DUMPTOFILE":
			log.Printf("Client %v: DUMPTOFILE triggered", client.ID)
			// Use the dumpFile pointer value
			resp = store.DumpToFile(*dumpFile) 

		case "DUMP":
            // ... (Dump logic remains the same) ...
			log.Printf("Client %v: DUMP full store", client.ID)
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
			log.Printf("Client %v: SET key='%s'", client.ID, req.Key)
			resp = Response{Status: "OK", Op: "SET", Key: req.Key}

		case "GET":
			store.Lock.RLock()
			val, exists := store.Data[req.Key]
			store.Lock.RUnlock()
			if exists {
				resp = Response{Status: "OK", Op: "GET", Key: req.Key, Value: val}
				log.Printf("Client %v: GET key='%s' -> FOUND", client.ID, req.Key)
			} else {
				resp = Response{Status: "NOT_FOUND", Op: "GET", Key: req.Key}
				log.Printf("Client %v: GET key='%s' -> NOT_FOUND", client.ID, req.Key)
			}

		case "DELETE":
			store.Lock.Lock()
			_, exists := store.Data[req.Key]
			if exists {
				delete(store.Data, req.Key)
				store.Lock.Unlock()
				resp = Response{Status: "OK", Op: "DELETE", Key: req.Key}
				log.Printf("Client %v: DELETE key='%s' -> SUCCESS", client.ID, req.Key)
			} else {
				store.Lock.Unlock()
				resp = Response{Status: "NOT_FOUND", Op: "DELETE", Key: req.Key}
				log.Printf("Client %v: DELETE key='%s' -> NOT_FOUND", client.ID, req.Key)
			}

		default:
			resp = Response{Status: "ERROR", Message: "Unknown operation"}
		}
        
        // Ensure SenderId is always included in the response payload when sending
        resp.SenderId = client.ID

		client.WriteJSON(resp)
	}
}

// --- Initialization and Main Server Start (No changes) ---

func setupFlags() {
	// Define the flags using the standard flag package
	
	// Server/Network Flags
	// Host default is set to "localhost" (127.0.0.1)
	host = flag.String("h", "localhost", "Host (long: --host): The interface the server listens on (default: localhost).")
	port = flag.String("p", "9999", "Port (long: --port): The TCP port the server listens on.")
	flag.StringVar(host, "host", "localhost", "Host (short: -h): The interface the server listens on (default: localhost).")
	flag.StringVar(port, "port", "9999", "Port (short: -p): The TCP port the server listens on.")

	// Security (mTLS) Flags
	certFile = flag.String("c", "server.crt", "Server Cert Path (long: --cert).")
	keyFile = flag.String("k", "server.key", "Server Private Key Path (long: --key).")
	
	// Client CA flag for consistency with client config
	clientCA = flag.String("ca", "ca.crt", "Root CA Cert Path (long: --ca-cert) to verify clients.")
	flag.StringVar(clientCA, "ca-cert", "ca.crt", "Root CA Certificate Path (short: -ca) to verify clients.")

	// Data Persistence Flags
	dumpFile = flag.String("dump-file", "store_dump.json", "Data Dump File: Filename for persistence of the main data store.")
	dumpIntervalStr = flag.String("dt", "5m", "Periodic Dump Interval (long: --dump-time): Duration for automatically saving the store (e.g., 5s, 1m, 30m). Set to 0s to disable.") 
    flag.StringVar(dumpIntervalStr, "dump-time", "5m", "Periodic Dump Interval (short: -dt): Duration for automatically saving the store (e.g., 5s, 1m, 30m). Set to 0s to disable.")

	flag.Parse()
}

func main() {
	// Set up command-line flags
	setupFlags()

	// 1. Start Periodic Dump
	startPeriodicDump()

	// 2. Load CA to verify clients
	caCert, err := os.ReadFile(*clientCA)
	if err != nil {
		log.Fatalf("Error reading client CA cert %s: %v", *clientCA, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 3. Load Server Cert/Key
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Error loading server key pair %s/%s: %v", *certFile, *keyFile, err)
	}

	// Configure mTLS to require and verify the client certificate.
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, 
	}
    
	// 4. Start Listener
	addr := *host + ":" + *port
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Fatalf("Listener error: %v", err)
	}
	defer func() {
		// Log server closure
		log.Printf("Server closed listening on %s", addr)
		listener.Close()
	}()

	// Log server start
	log.Printf("Server started listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn)
	}
}