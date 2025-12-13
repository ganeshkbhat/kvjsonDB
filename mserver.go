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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Log Type Constants ---
const (
	LOG_INFO    = "INFO"
	LOG_ERROR   = "ERROR"
	LOG_WARN    = "WARN"
	LOG_ACTIVITY = "ACCESS"
	LOG_FATAL   = "FATAL"
)

// --- Configuration Variables (Server Flags) ---
var (
	// Network
	host *string
	port *string
	// Security (mTLS)
	certFile *string
	keyFile  *string
	clientCA *string
	// Persistence
	storeFile    *string    // Default for client DUMPTOFILE and periodic dump
	exitDumpFile *string    // Dedicated file for final graceful exit
	dumpTimeStr *string
    // Initial Load
    loadFile    *string 
)

// Global State
var (
	dataStore       = make(map[string]interface{})
	dataMutex       sync.RWMutex
	clientIDCounter int64 = 0
    clients         = make(map[string]net.Conn) 
)

// Request structure (The input must conform to this JSON structure)
type Request struct {
	Op       string      `json:"op"`
	Key      string      `json:"key,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Filename string      `json:"filename,omitempty"` 
	Term     interface{} `json:"term,omitempty"`
	Message  string      `json:"message,omitempty"`
	NewID    interface{} `json:"newId,omitempty"`
}

// Response structure (The output will always conform to this JSON structure)
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

// --- Structured Logger ---

// accessLogger provides an Apache-like log format with extra structure.
func accessLogger(logType, fileFunc, clientAddr, operation, key, message string) {
	// Derive server address from flags
	serverAddr := fmt.Sprintf("%s:%s", *host, *port)
    
    // Default the client address if not provided (e.g., for internal server actions)
    if clientAddr == "" {
        clientAddr = "INTERNAL"
    }

	logMsg := fmt.Sprintf(
		"| %-6s | %s | S:%s | C:%-20s | %-25s | %-12s | KEY:%-15s | %s",
		logType,
		time.Now().Format("2006-01-02 15:04:05"),
		serverAddr,
		clientAddr,
		fileFunc,
		operation,
		key,
		message,
	)
	log.Println(logMsg)
}

// --- Initialization and Flags ---

func setupFlags() {
	// Network Flags
	host = flag.String("h", "localhost", "Host (long: --host): The interface the server listens on (default: localhost).")
	flag.StringVar(host, "host", "localhost", "Host (short: -h): The interface the server listens on (default: localhost).")
	port = flag.String("p", "9999", "Port (long: --port): The TCP port the server listens on.")
	flag.StringVar(port, "port", "9999", "Port (short: -p): The TCP port the server listens on.")

	// Security (mTLS) Flags
	certFile = flag.String("c", "server.crt", "Server Cert Path (long: --cert).")
	flag.StringVar(certFile, "cert", "server.crt", "Server Cert Path (short: -c).")
	keyFile = flag.String("k", "server.key", "Server Private Key Path (long: --key).")
	flag.StringVar(keyFile, "key", "server.key", "Server Private Key Path (short: -k).")
	
    // Client CA Flags (handling both short and long forms)
	clientCA = flag.String("ca", "ca.crt", "Root CA Cert Path (long: --ca-cert) to verify clients.")
	flag.StringVar(clientCA, "ca-cert", "ca.crt", "Root CA Certificate Path (short: -ca) to verify clients.")

	// Persistence Flags
    storeFile = flag.String("dump-file", "store_dump.json", "Data Dump File: Default filename for periodic persistence and client DUMPTOFILE operations.")
	
    exitDumpFile = flag.String("exit-dump-file", "", "Graceful Exit Dump File: Dedicated filename for the final dump upon server shutdown. Defaults to the value of --dump-file if not set.")

	dumpTimeStr = flag.String("dt", "5m", "Periodic Dump Interval (long: --dump-time): Duration for automatically saving the store (e.g., 5s, 1m, 30m). Set to 0s to disable.")
	flag.StringVar(dumpTimeStr, "dump-time", "5m", "Periodic Dump Interval (short: -dt): Duration for automatically saving the store (e.g., 5s, 1m, 30m). Set to 0s to disable.")
    
    // Initial Load Flag
    loadFile = flag.String("load-file", "", "Initial Load File: Filename to load data from at startup. Leave empty to skip loading.")

	flag.Parse()
    
    // Override standard log format to avoid duplication
    log.SetFlags(0)
    
    accessLogger(LOG_INFO, "main.setupFlags", "", "INIT_CONFIG", "", "Flags parsed successfully.")
}

// --- Server Helpers (Database Operations) ---

// loadData attempts to load the data store from the given file.
func loadData(filename string) error {
	if filename == "" {
        accessLogger(LOG_ERROR, "main.loadData", "", "LOAD_FAIL", "", "Filename cannot be empty.")
		return fmt.Errorf("filename cannot be empty")
	}
    
	if _, err := os.Stat(filename); os.IsNotExist(err) {
        // This is often expected, so only log as INFO/WARN during startup
		return fmt.Errorf("file not found: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
        accessLogger(LOG_ERROR, "main.loadData", "", "LOAD_FAIL", filename, fmt.Sprintf("Failed to read file: %v", err))
		return fmt.Errorf("failed to read load file %s: %w", filename, err)
	}
    
    var tempStore = make(map[string]interface{})
	if err := json.Unmarshal(data, &tempStore); err != nil {
        accessLogger(LOG_ERROR, "main.loadData", "", "LOAD_FAIL", filename, fmt.Sprintf("Failed to unmarshal JSON: %v", err))
		return fmt.Errorf("failed to unmarshal JSON from %s: %w", filename, err)
	}

    dataStore = tempStore
    accessLogger(LOG_INFO, "main.loadData", "", "LOAD_SUCCESS", filename, fmt.Sprintf("Successfully loaded %d keys.", len(dataStore)))
	return nil
}

// saveData saves the current data store to the specified or default dump file.
func saveData(filename string, opType string) error {
	dataMutex.RLock()
	defer dataMutex.RUnlock()

	// If no filename is provided (periodic/exit dump), use the default --dump-file.
	targetFile := filename
	if targetFile == "" {
		targetFile = *storeFile
	}

	data, err := json.MarshalIndent(dataStore, "", "  ")
	if err != nil {
        accessLogger(LOG_ERROR, "main.saveData", "", opType, targetFile, fmt.Sprintf("Failed to marshal data: %v", err))
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(targetFile, data, 0644); err != nil {
        accessLogger(LOG_ERROR, "main.saveData", "", opType, targetFile, fmt.Sprintf("Failed to write file: %v", err))
		return fmt.Errorf("failed to write data to %s: %w", targetFile, err)
	}
    accessLogger(LOG_INFO, "main.saveData", "", opType, targetFile, fmt.Sprintf("Data dumped successfully. Key count: %d", len(dataStore)))
	return nil
}

// startPeriodicDump starts a ticker to save the data periodically.
func startPeriodicDump() {
	duration, err := time.ParseDuration(*dumpTimeStr)
	if err != nil {
		accessLogger(LOG_FATAL, "main.startPeriodicDump", "", "DUMP_CONFIG", *dumpTimeStr, fmt.Sprintf("Invalid dump-time duration: %v", err))
		log.Fatalf("Invalid dump-time duration %s: %v", *dumpTimeStr, err)
	}

	if duration <= 0 {
		accessLogger(LOG_INFO, "main.startPeriodicDump", "", "DUMP_CONFIG", "", "Periodic dumping disabled.")
		return
	}

	ticker := time.NewTicker(duration)
	accessLogger(LOG_INFO, "main.startPeriodicDump", "", "DUMP_CONFIG", *storeFile, fmt.Sprintf("Periodic dumping started every %s.", duration))

	go func() {
		for {
			select {
			case <-ticker.C:
				// Use "PERIODIC_DUMP" as the operation type for logging
				if err := saveData("", "PERIODIC_DUMP"); err != nil { 
					accessLogger(LOG_ERROR, "main.startPeriodicDump", "", "PERIODIC_DUMP_FAIL", *storeFile, fmt.Sprintf("Periodic dump failed: %v", err))
				}
			}
		}
	}()
}

// --- Server Helpers (Response Handling) (UNCHANGED) ---

func newResponse(status string, op string, message string, senderID string, key string, value interface{}, results interface{}) Response {
	return Response{
		Status:   status,
		Op:       op,
		Message:  message,
		SenderId: senderID,
		Key:      key,
		Value:    value,
		Results:  results,
		Time:     time.Now().Format(time.RFC3339),
	}
}

func sendResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		accessLogger(LOG_ERROR, "main.sendResponse", conn.RemoteAddr().String(), resp.Op, resp.Key, fmt.Sprintf("Error marshaling response: %v", err))
		return
	}
	conn.Write(append(data, '\n'))
}

// --- Core Request Handling ---

func handleRequest(clientID string, conn net.Conn, rawReq []byte) {
	var req Request
	if err := json.Unmarshal(rawReq, &req); err != nil {
		sendResponse(conn, newResponse("ERROR", "", "Invalid JSON request.", clientID, "", nil, nil))
		accessLogger(LOG_ERROR, "main.handleRequest", conn.RemoteAddr().String(), "RECV_REQUEST", "", fmt.Sprintf("Invalid JSON received: %s", string(rawReq)))
		return
	}
	
	// Log the incoming command request
	op := strings.ToUpper(req.Op)
	clientAddr := conn.RemoteAddr().String()
	
	accessLogger(LOG_ACTIVITY, "main.handleRequest", clientAddr, op, req.Key, fmt.Sprintf("Request received. ClientID: %s", clientID))


	var resp Response

	dataMutex.Lock()
	defer dataMutex.Unlock()
	
	switch op {
	case "SET":
		if req.Key == "" || req.Value == nil {
			resp = newResponse("ERROR", op, "Missing key or value.", clientID, "", nil, nil)
		} else {
			dataStore[req.Key] = req.Value
			resp = newResponse("OK", op, "Key set successfully.", clientID, req.Key, nil, nil)
		}
	case "GET":
		if req.Key == "" {
			resp = newResponse("ERROR", op, "Missing key.", clientID, "", nil, nil)
		} else if val, ok := dataStore[req.Key]; ok {
			resp = newResponse("OK", op, "Key retrieved successfully.", clientID, req.Key, val, nil)
		} else {
			resp = newResponse("NOT_FOUND", op, "Key not found.", clientID, req.Key, nil, nil)
		}
	case "DELETE":
		if req.Key == "" {
			resp = newResponse("ERROR", op, "Missing key.", clientID, "", nil, nil)
		} else if _, ok := dataStore[req.Key]; ok {
			delete(dataStore, req.Key)
			resp = newResponse("OK", op, "Key deleted successfully.", clientID, req.Key, nil, nil)
		} else {
			resp = newResponse("NOT_FOUND", op, "Key not found.", clientID, req.Key, nil, nil)
		}
	case "SEARCH", "SEARCHKEY":
		results := make(map[string]interface{})
		termStr := fmt.Sprintf("%v", req.Term)
		
		for k, v := range dataStore {
			vStr := fmt.Sprintf("%v", v)
			if strings.Contains(strings.ToLower(k), strings.ToLower(termStr)) || strings.Contains(strings.ToLower(vStr), strings.ToLower(termStr)) {
				results[k] = v
			}
		}
		
		resp = newResponse("OK", op, fmt.Sprintf("Search completed. Found %d results.", len(results)), clientID, "", nil, results)

	case "DUMP":
		dataMutex.Unlock() 
		
		respData, _ := json.Marshal(dataStore)
		var temp interface{}
		json.Unmarshal(respData, &temp)
		
		dataMutex.Lock() 
		
		resp = newResponse("OK", op, "Data dump retrieved.", clientID, "", nil, nil)
		resp.Data = temp

	case "DUMPTOFILE":
		dataMutex.Unlock() 
		
		filenameToDump := req.Filename
		
		// Use "CLIENT_DUMP" as the operation type for logging
		if err := saveData(filenameToDump, "CLIENT_DUMP"); err != nil {
			resp = newResponse("ERROR", op, fmt.Sprintf("Failed to save data: %v", err), clientID, "", nil, nil)
		} else {
			finalFilename := filenameToDump
			if finalFilename == "" {
				finalFilename = *storeFile
			}
			resp = newResponse("OK", op, fmt.Sprintf("Data dumped successfully to %s.", finalFilename), clientID, "", nil, nil)
		}
		
		dataMutex.Lock() 

	case "LOAD":
		dataMutex.Unlock() 
		
		if req.Filename == "" {
			resp = newResponse("ERROR", op, "Missing filename for LOAD operation.", clientID, "", nil, nil)
		} else if err := loadData(req.Filename); err != nil {
			resp = newResponse("ERROR", op, fmt.Sprintf("Failed to load data: %v", err), clientID, "", nil, nil)
		} else {
			resp = newResponse("OK", op, fmt.Sprintf("Data loaded from %s.", req.Filename), clientID, "", nil, nil)
		}
		
		dataMutex.Lock() 

	case "BROADCAST":
		if req.Message == "" {
			resp = newResponse("ERROR", op, "Missing message.", clientID, "", nil, nil)
		} else {
			sendResponse(conn, newResponse("OK", op, "Broadcast sent.", clientID, "", nil, nil)) 
			
			dataMutex.Unlock() 
			broadcastMessage(clientID, req.Message)
			dataMutex.Lock() 
			return 
		}
        
	case "SETID":
        newID := fmt.Sprintf("%v", req.NewID)
        
		dataMutex.Unlock() 

        dataMutex.Lock() 
        delete(clients, clientID)
        clients[newID] = conn
        dataMutex.Unlock() 

		dataMutex.Lock() 
		
		resp = newResponse("OK", op, fmt.Sprintf("Client ID successfully updated to %s.", newID), newID, "", nil, nil)
		
		// Log the ID change
		accessLogger(LOG_INFO, "main.handleRequest", clientAddr, "SET_ID", newID, fmt.Sprintf("ID changed from %s", clientID))
		
	default:
		resp = newResponse("ERROR", op, fmt.Sprintf("Unknown operation: %s", op), clientID, "", nil, nil)
	}

	sendResponse(conn, resp)
}

// broadcastMessage sends a JSON broadcast message to all connected clients except the sender.
func broadcastMessage(senderID string, message string) {
	broadcastResp := newResponse("BROADCAST", "BROADCAST", message, senderID, "", nil, nil)
	
	dataMutex.RLock()
	defer dataMutex.RUnlock()

	accessLogger(LOG_ACTIVITY, "main.broadcastMessage", senderID, "BROADCAST_SEND", "", fmt.Sprintf("Sending message to %d clients.", len(clients)-1))

	for clientID, clientConn := range clients {
		if clientID != senderID {
			go sendResponse(clientConn, broadcastResp)
		}
	}
}

// --- Connection Handler ---

func handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	
	dataMutex.Lock()
	clientIDCounter++
	id := fmt.Sprintf("%d:%s", clientIDCounter, remoteAddr)
    clients[id] = conn
	dataMutex.Unlock()
    
	accessLogger(LOG_INFO, "main.handleConnection", remoteAddr, "CONNECT", id, "New client connected.")
    
	statusResp := newResponse("STATUS", "INIT", "Connection established.", id, "", nil, nil)
	sendResponse(conn, statusResp)

	scanner := bufio.NewScanner(conn)
	currentClientID := id
	
	for scanner.Scan() {
		rawReq := scanner.Bytes()
		clientIDAtRequestTime := currentClientID 
        
		go handleRequest(clientIDAtRequestTime, conn, rawReq)
	}

	conn.Close()
    
	dataMutex.Lock()
    delete(clients, currentClientID)
	dataMutex.Unlock()
	
	// Log disconnect
	if scanner.Err() != nil {
		accessLogger(LOG_ERROR, "main.handleConnection", remoteAddr, "DISCONNECT", currentClientID, fmt.Sprintf("Client connection closed with error: %v", scanner.Err()))
	} else {
		accessLogger(LOG_INFO, "main.handleConnection", remoteAddr, "DISCONNECT", currentClientID, "Client disconnected gracefully.")
	}
}

// --- Main Server Function ---

func main() {
	setupFlags()
	
	accessLogger(LOG_INFO, "main.main", "", "SERVER_START", "", fmt.Sprintf("Server starting on %s:%s...", *host, *port))

    // Set the file path for the graceful shutdown dump. Default to --dump-file.
    finalDumpFile := *exitDumpFile
    if finalDumpFile == "" {
        finalDumpFile = *storeFile
    }

    // --- Signal Handling for Graceful Exit ---
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        sig := <-sigChan
        accessLogger(LOG_WARN, "main.signalHandler", "", "GRACEFUL_EXIT", finalDumpFile, fmt.Sprintf("Received signal %v. Initiating shutdown.", sig))

        // Perform final dump using the determined exit file
		// Use "EXIT_DUMP" as the operation type for logging
        if err := saveData(finalDumpFile, "EXIT_DUMP"); err != nil {
            accessLogger(LOG_FATAL, "main.signalHandler", "", "EXIT_DUMP_FAIL", finalDumpFile, fmt.Sprintf("Failed final data dump: %v", err))
        } else {
            accessLogger(LOG_INFO, "main.signalHandler", "", "EXIT_SUCCESS", finalDumpFile, "Final data store dumped. Shutting down.")
        }

        dataMutex.Lock()
        for _, conn := range clients {
            conn.Close()
        }
        dataMutex.Unlock()

        os.Exit(0)
    }()
    // --------------------------------------------------

	// --- 1. Load Data from Store File at Startup ---
	if *loadFile != "" {
		dataMutex.Lock()
		if err := loadData(*loadFile); err != nil { 
			// Load failure handled within loadData log, here we just check for the error type
			accessLogger(LOG_WARN, "main.main", "", "INIT_LOAD", *loadFile, fmt.Sprintf("Initial load error: %v.", err))
		}
		dataMutex.Unlock()
	} else {
        accessLogger(LOG_INFO, "main.main", "", "INIT_LOAD", "", "No load-file specified. Starting with an empty store.")
    }

	// --- 2. Start Periodic Dump ---
	startPeriodicDump()

	// --- 3. Setup mTLS Configuration ---
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		accessLogger(LOG_FATAL, "main.main", "", "TLS_CONFIG", *certFile, fmt.Sprintf("Failed to load server key pair: %v", err))
		log.Fatalf("Failed to load server key pair: %v", err)
	}

	caCert, err := os.ReadFile(*clientCA)
	if err != nil {
		accessLogger(LOG_FATAL, "main.main", "", "TLS_CONFIG", *clientCA, fmt.Sprintf("Failed to read client CA cert: %v", err))
		log.Fatalf("Failed to read client CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// --- 4. Start Listener ---
	addr := *host + ":" + *port
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		accessLogger(LOG_FATAL, "main.main", "", "LISTEN_FAIL", addr, fmt.Sprintf("Failed to start listener: %v", err))
		log.Fatalf("Failed to start listener on %s: %v", addr, err)
	}
	defer listener.Close()

	accessLogger(LOG_INFO, "main.main", "", "LISTEN_SUCCESS", addr, "Server listening securely. Awaiting connections.")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return 
			}
			accessLogger(LOG_ERROR, "main.main", "", "ACCEPT_FAIL", addr, fmt.Sprintf("Error accepting connection: %v", err))
			continue
		}
		go handleConnection(conn)
	}
}