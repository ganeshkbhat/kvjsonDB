package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- Constants ---
const blobStorageDir = "blob_storage"

// --- Client TLS Configuration Struct ---
type ClientTLSConfig struct {
	CACertPath string
	CertPath   string
	KeyPath    string
	Host       string 
	Port       int
}

// --- Command-Line Flags ---
var (
	modePtr *string
	loadPtr *string 
	dumpFilenamePtr *string
	logFilePtr *string 
	dtPtr *time.Duration 
	
	hostPtr *string 
	portPtr *int 

	// TLS FLAGS 
	caCertPtr *string 
	certPtr *string
	keyPtr *string
)

// --- Global Client State ---
var (
	currentConn net.Conn
	currentReader *bufio.Reader
	dynamicConfig ClientTLSConfig 
)

// --- Global Server State ---
var db = JSONDB{Store: make(map[string]interface{})}
// Atomic counter for unique connection IDs
var connectionCounter uint64

// --- Core Data Structures ---
type JSONDB struct {
	Store map[string]interface{}
	Lock  sync.RWMutex
}

type Request struct {
	Op          string      `json:"op"`
	Key         string      `json:"key,omitempty"`
	Value       interface{} `json:"value,omitempty"`
	Filename    string      `json:"filename,omitempty"`
	SearchValue string      `json:"searchValue,omitempty"` 
	KeySubstring string     `json:"keySubstring,omitempty"`
	BlobSize    int64       `json:"blobSize,omitempty"` 
	ClientPath  string      `json:"clientPath,omitempty"` 
}

type Response struct {
	Status        string      `json:"status"`
	Op            string      `json:"op,omitempty"`
	Message       string      `json:"message,omitempty"`
	Key           string      `json:"key,omitempty"`
	Value         interface{} `json:"value,omitempty"`
	SearchResults map[string]interface{} `json:"searchResults,omitempty"` 
	DeletedCount  int                    `json:"deletedCount,omitempty"`
	BlobSize      int64       `json:"blobSize,omitempty"` 
	BlobPath      string      `json:"blobPath,omitempty"` 
}


// ==========================================
//               LOGGING SETUP
// ==========================================

// setupFileLogger configures the standard log package to write to both Stderr and a log file.
func setupFileLogger() {
	if *logFilePtr == "" {
		// Log remains console-only if -log="" or is explicitly empty
		return 
	}

	logFile, err := os.OpenFile(*logFilePtr, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", *logFilePtr, err)
	}
	
	// Create a multi-writer to send logs to both the file and standard error (console)
	multiWriter := io.MultiWriter(os.Stderr, logFile)
	
	// Set the output for the standard log package
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("SERVER_INFO: Logging initialized. Output directed to console and file: %s", *logFilePtr)
}

// ==========================================
//               PERSISTENCE LOGIC
// ==========================================

// loadStoreFromFile loads data from a file, merging (updating/inserting) keys into the current store.
func loadStoreFromFile(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("DATA_LOAD_FAIL: Data file not found: %s. Store remains unchanged.", filename)
			return
		}
		log.Printf("DATA_LOAD_ERROR: Error reading data file %s: %v", filename, err)
		return
	}

	db.Lock.Lock()
	defer db.Lock.Unlock()

	newStore := make(map[string]interface{})
	if err := json.Unmarshal(data, &newStore); err != nil {
		log.Printf("DATA_LOAD_ERROR: Error unmarshalling data from file %s: %v. Store remains unchanged.", filename, err)
		return
	}
	
	importedCount := 0
	for key, value := range newStore {
		// Overwrite existing key or insert new key (MERGE/UPDATE)
		db.Store[key] = value
		importedCount++
	}
	
	log.Printf("DATA_LOAD_SUCCESS: Successfully merged data from %s. Keys updated/added: %d. Total items now: %d", filename, importedCount, len(db.Store))
}

// dumpToFile saves the current database state to a file.
func dumpToFile(filename string, source string) error {
	db.Lock.RLock()
	data, err := json.MarshalIndent(db.Store, "", "  ")
	db.Lock.RUnlock()

	if err != nil {
		return fmt.Errorf("error marshalling data: %w", err)
	}

	tmpFilename := filename + ".tmp"
	if err := os.WriteFile(tmpFilename, data, 0644); err != nil {
		return fmt.Errorf("error writing temporary file: %w", err)
	}

	if err := os.Rename(tmpFilename, filename); err != nil {
		return fmt.Errorf("error renaming temporary file: %w", err)
	}
	
	log.Printf("DATA_DUMP_SUCCESS: [%s] Database state successfully dumped to %s", source, filename)
	return nil
}

// ==========================================
//               INITIALIZATION
// ==========================================

func init() {
	defaultCert := "server.crt"
	defaultKey := "server.key"
	
	// Determine default certs based on intended run mode for convenience
	for _, arg := range os.Args {
		if arg == "-s=shell" || arg == "--s=shell" {
			defaultCert = "client.crt"
			defaultKey = "client.key"
			break
		}
	}

	// Mode and Persistence Flags
	modePtr = flag.String("s", "db", "Server mode: 'db' (run server) or 'shell' (run client shell)")
	loadPtr = flag.String("l", "", "Load initial data from this file (defaults to --dump-file if not set)")
	dumpFilenamePtr = flag.String("dump-file", "store_dump.json", "Default filename for persistence dumps")
	logFilePtr = flag.String("log", "server.log", "Path to the log file. Defaults to 'server.log' in the execution directory (server only).") 
	dtPtr = flag.Duration("dt", 0, "Duration for periodical persistence dump (e.g., 30m, 1h0s). If 0 or not specified, no periodic dump occurs.")
	
	// Connection Flags (used for initial connection/listen)
	hostPtr = flag.String("h", "localhost", "The host interface or address for the server to listen on or the client to connect to.")
	portPtr = flag.Int("p", 9999, "The port number for the server to listen on or the client to connect to.")

	// TLS Flags
	caCertPtr = flag.String("ca-cert", "ca.crt", "Path to the root CA certificate.")
	certPtr = flag.String("cert", defaultCert, "Path to the component's (server/client) certificate.")
	keyPtr = flag.String("key", defaultKey, "Path to the component's (server/client) private key.")
	
	flag.Parse()
}

// --- Main Entry Point ---

func main() {
	setupFileLogger() // INITIALIZE LOGGER FIRST

	// Mandatory TLS check
	if *modePtr == "db" && (*certPtr == "" || *keyPtr == "") {
		log.Fatalf("CONFIG_ERROR: TLS mode requires --cert (default: server.crt) and --key (default: server.key) flags to be set for the server.")
	}
	if *modePtr == "shell" && (*certPtr == "" || *keyPtr == "") {
		log.Fatalf("CONFIG_ERROR: TLS mode requires --cert (default: client.crt) and --key (default: client.key) flags to be set for the client.")
	}

	addr := net.JoinHostPort(*hostPtr, strconv.Itoa(*portPtr))
	
	switch *modePtr {
	case "db":
		log.Printf("SERVER_START: Running in DB mode.")
		// Ensure BLOB directory exists
		if err := os.MkdirAll(blobStorageDir, 0755); err != nil {
			log.Fatalf("CONFIG_ERROR: Failed to create BLOB storage directory '%s': %v", blobStorageDir, err)
		}
		
		// Emergency dump on panic
		defer func() {
			if r := recover(); r != nil {
				log.Printf("CRITICAL_PANIC: Panic detected: %v. Attempting emergency persistence dump.", r)
				// Use "CRASH" as the source for emergency dump
				if err := dumpToFile(*dumpFilenamePtr, "CRASH"); err != nil {
					log.Printf("EMERGENCY_DUMP_FAILED: %v", err)
				} else {
					log.Printf("EMERGENCY_DUMP_SUCCESS: Data persisted before crash.")
				}
				panic(r) 
			}
		}()

		// Load initial data
		fileToLoad := *loadPtr
		if fileToLoad == "" {
			fileToLoad = *dumpFilenamePtr
		}
		loadStoreFromFile(fileToLoad) 
		
		runServer(addr)
		
	case "shell":
		log.Printf("CLIENT_START: Running in Shell mode.")
		// Initialize dynamic configuration with command-line flag values
		dynamicConfig = ClientTLSConfig{
			Host: *hostPtr,
			Port: *portPtr,
			CACertPath: *caCertPtr,
			CertPath: *certPtr,
			KeyPath: *keyPtr,
		}
		runShell()
		
	default:
		log.Printf("CONFIG_ERROR: Invalid mode specified: %s", *modePtr)
		fmt.Println("Error: You must specify a mode using -s.")
		flag.Usage()
		os.Exit(1)
	}
}

// ==========================================
//               SERVER LOGIC
// ==========================================

func getServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(*certPtr, *keyPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate/key (%s, %s): %w", *certPtr, *keyPtr, err)
	}
	caCert, err := os.ReadFile(*caCertPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate (%s): %w", *caCertPtr, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, 
		MinVersion:   tls.VersionTLS12,
	}
	return config, nil
}

// StartDumpScheduler initiates the periodic dumping routine if dtPtr is greater than 0.
func StartDumpScheduler() *time.Ticker {
	duration := *dtPtr
	if duration <= 0 {
		log.Println("SCHEDULER_INFO: Periodic persistence disabled (dt=0).")
		return nil
	}

	// Ensure duration is not too short
	if duration < 10 * time.Second {
		duration = 10 * time.Second
		log.Printf("SCHEDULER_WARNING: Dump interval too short. Setting minimum to %s.", duration)
	}

	ticker := time.NewTicker(duration)
	log.Printf("SCHEDULER_START: Periodic persistence enabled. Dumping every %s to %s", duration, *dumpFilenamePtr)

	go func() {
		for range ticker.C {
			// Use "PERIODIC" as the source for scheduled dump
			if err := dumpToFile(*dumpFilenamePtr, "PERIODIC"); err != nil {
				log.Printf("SCHEDULER_DUMP_FAILED: %v", err)
			}
		}
	}()
	return ticker
}


func runServer(addr string) {
	// Start the periodic dump scheduler
	ticker := StartDumpScheduler()
	if ticker != nil {
		defer ticker.Stop()
	}

	// Graceful shutdown on signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh 
		log.Printf("SERVER_SHUTDOWN_INITIATED: Received signal %v. Initiating mandatory graceful persistence dump...", sig)

		// Use "SHUTDOWN" as the source for graceful dump
		if err := dumpToFile(*dumpFilenamePtr, "SHUTDOWN"); err != nil {
			log.Fatalf("SERVER_SHUTDOWN_ERROR: Graceful dump FAILED: %v", err)
		}
		
		log.Println("SERVER_SHUTDOWN_COMPLETE: Persistence successful. Shutting down server.")
		os.Exit(0)
	}()

	// Start listener
	tlsConfig, err := getServerTLSConfig()
	if err != nil {
		log.Fatalf("CONFIG_ERROR: Failed to configure TLS server: %v", err)
	}
	
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Printf("SERVER_INFO: JSON DB Server running on %s in mTLS Mode (Dump file: %s)", addr, *dumpFilenamePtr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				break 
			}
			log.Println("SERVER_ACCEPT_ERROR:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	// Generate a unique ID for this connection
	connID := atomic.AddUint64(&connectionCounter, 1)
	
	defer conn.Close()
	
	// Default client identifier is UNKNOWN, will be replaced by CN
	clientCN := "UNKNOWN"
	
	// Extract IP and Port for logging
	remoteAddr := conn.RemoteAddr().String()
	clientIP, clientPort, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		clientIP = remoteAddr
		clientPort = "N/A"
	}
	
	// Attempt to perform TLS handshake and extract CN
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// Handshake is typically performed on first read/write, but doing it here ensures we get the CN immediately.
		if err := tlsConn.Handshake(); err == nil {
			if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				clientCN = tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
			}
		}
	}

	// UPDATED: Log prefix format: [ConnID:X:ClientID][IP:PORT]
	logPrefix := fmt.Sprintf("[ConnID:%d:%s][%s:%s]", connID, clientCN, clientIP, clientPort)

	log.Printf("%s CONNECTION_OPEN", logPrefix)
	
	// Send the full connection identifier back to the client
	initialMessage := fmt.Sprintf("Connected to JSON DB Server via mTLS. Your identifier is [ConnID:%d:%s].", connID, clientCN)
	writeJSON(conn, Response{Status: "INFO", Message: initialMessage})

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) 

	for scanner.Scan() {
		rawMessage := scanner.Bytes()
		var req Request
		
		if err := json.Unmarshal(rawMessage, &req); err != nil {
			log.Printf("%s REQUEST_ERROR Invalid JSON: %s", logPrefix, rawMessage)
			writeJSON(conn, Response{Status: "ERROR", Message: "Invalid JSON format."})
			continue
		}

		op := strings.ToUpper(req.Op)
		
		// Log the incoming command
		log.Printf("%s REQUEST_IN OP: %s Key: %s", logPrefix, op, req.Key)

		switch op {
		case "PUTBLOB":
			handlePutBlobRequest(conn, req, clientCN, logPrefix)
		case "GETBLOB":
			handleGetBlobRequest(conn, req, clientCN, logPrefix)
		case "DELETEBLOB":
			handleDeleteBlobRequest(conn, req, clientCN, logPrefix)
		case "DUMP": 
			handleDumpRequest(conn, req, clientCN, logPrefix)
		case "LOAD": 
			handleLoadRequest(conn, req, clientCN, logPrefix)
		default:
			handleRequest(conn, req, clientCN, logPrefix)
		}
	}
	log.Printf("%s CONNECTION_CLOSED", logPrefix)
}

// --- BLOB Handling Functions (Server Side) ---

func handleDeleteBlobRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	if req.Key == "" {
		writeJSON(conn, Response{Status: "ERROR", Op: "DELETEBLOB", Message: "Key is required for DELETEBLOB."})
		log.Printf("%s OP_FAILURE OP: DELETEBLOB Key: (empty) Error: Missing key.", logPrefix)
		return
	}

	db.Lock.Lock()
	defer db.Lock.Unlock()

	value, ok := db.Store[req.Key]
	if !ok {
		writeJSON(conn, Response{Status: "NOT_FOUND", Op: "DELETEBLOB", Key: req.Key, Message: "Key not found."})
		log.Printf("%s OP_FAILURE OP: DELETEBLOB Key: %s Status: NOT_FOUND.", logPrefix, req.Key)
		return
	}

	metadata, isBlob := value.(map[string]interface{})
	if !isBlob || metadata["type"] != "BLOB" {
		writeJSON(conn, Response{Status: "ERROR", Op: "DELETEBLOB", Key: req.Key, Message: "Key exists but is not a BLOB object. Use DELETE to remove."})
		log.Printf("%s OP_FAILURE OP: DELETEBLOB Key: %s Error: Key is not BLOB.", logPrefix, req.Key)
		return
	}
	
	path, pOK := metadata["path"].(string)
	if pOK && path != "" {
		if err := os.Remove(path); err != nil {
			log.Printf("%s BLOB_FILE_ERROR OP: DELETEBLOB Key: %s Filename: %s Error: Failed to delete BLOB file.", logPrefix, req.Key, path)
		} else {
			log.Printf("%s BLOB_FILE_DELETED OP: DELETEBLOB Key: %s Filename: %s", logPrefix, req.Key, path)
		}
	}

	delete(db.Store, req.Key)

	writeJSON(conn, Response{
		Status: "OK", 
		Op: "DELETEBLOB", 
		Key: req.Key,
		Message: "BLOB object and associated file deleted successfully.",
	})
	log.Printf("%s OP_SUCCESS OP: DELETEBLOB Key: %s", logPrefix, req.Key)
}


func handlePutBlobRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	if req.Key == "" || req.ClientPath == "" || req.BlobSize <= 0 {
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: "Key, ClientPath, and BlobSize are required."})
		log.Printf("%s OP_FAILURE OP: PUTBLOB Key: %s Error: Missing parameters.", logPrefix, req.Key)
		return
	}

	baseName := filepath.Base(req.ClientPath)
	serverBlobPath := filepath.Join(blobStorageDir, req.Key+"_"+baseName)

	file, err := os.Create(serverBlobPath)
	if err != nil {
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: fmt.Sprintf("Failed to create file: %v", err)})
		log.Printf("%s BLOB_ERROR OP: PUTBLOB Key: %s Error: File creation failed: %v", logPrefix, req.Key, err)
		return
	}
	defer file.Close()
	
	log.Printf("%s BLOB_TRANSFER_START OP: PUTBLOB Key: %s Filename: %s Size: %d bytes.", logPrefix, req.Key, serverBlobPath, req.BlobSize)
	
	// Read the BLOB data immediately following the request JSON
	n, err := io.CopyN(file, conn, req.BlobSize)

	if err != nil {
		os.Remove(serverBlobPath) 
		log.Printf("%s BLOB_TRANSFER_ERROR OP: PUTBLOB Key: %s Error: Transfer failed after %d bytes: %v", logPrefix, req.Key, n, err)
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: fmt.Sprintf("Transfer failed after %d bytes: %v", n, err)})
		return
	}
	
	if n != req.BlobSize {
		os.Remove(serverBlobPath)
		log.Printf("%s BLOB_TRANSFER_ERROR OP: PUTBLOB Key: %s Error: Size mismatch, expected %d, received %d", logPrefix, req.Key, req.BlobSize, n)
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: fmt.Sprintf("Size mismatch: Expected %d bytes, received %d bytes.", req.BlobSize, n)})
		return
	}

	db.Lock.Lock()
	db.Store[req.Key] = map[string]interface{}{
		"type": "BLOB",
		"path": serverBlobPath,
		"size": req.BlobSize,
		"originalName": baseName,
	}
	db.Lock.Unlock()

	log.Printf("%s OP_SUCCESS OP: PUTBLOB Key: %s Filename: %s", logPrefix, req.Key, serverBlobPath)
	writeJSON(conn, Response{
		Status: "OK", 
		Op: "PUTBLOB", 
		Message: fmt.Sprintf("BLOB stored successfully. Size: %d bytes.", req.BlobSize),
		BlobSize: req.BlobSize,
		BlobPath: serverBlobPath,
	})
}

func handleGetBlobRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	db.Lock.RLock()
	value, ok := db.Store[req.Key]
	db.Lock.RUnlock()

	if !ok {
		writeJSON(conn, Response{Status: "NOT_FOUND", Op: "GETBLOB", Key: req.Key, Message: "Key not found."})
		log.Printf("%s OP_FAILURE OP: GETBLOB Key: %s Status: NOT_FOUND.", logPrefix, req.Key)
		return
	}

	metadata, ok := value.(map[string]interface{})
	if !ok || metadata["type"] != "BLOB" {
		writeJSON(conn, Response{Status: "ERROR", Op: "GETBLOB", Message: "Key is not a BLOB object."})
		log.Printf("%s OP_FAILURE OP: GETBLOB Key: %s Error: Key is not BLOB.", logPrefix, req.Key)
		return
	}
	
	serverBlobPath, pathOK := metadata["path"].(string)
	blobSizeFloat, sizeOK := metadata["size"].(float64) 
	blobSize := int64(blobSizeFloat)

	if !pathOK || !sizeOK || serverBlobPath == "" || blobSize <= 0 {
		writeJSON(conn, Response{Status: "ERROR", Op: "GETBLOB", Message: "BLOB metadata is corrupted."})
		log.Printf("%s OP_FAILURE OP: GETBLOB Key: %s Error: BLOB metadata corrupted.", logPrefix, req.Key)
		return
	}
	
	// 1. Send metadata response
	writeJSON(conn, Response{
		Status: "OK", 
		Op: "GETBLOB", 
		Key: req.Key,
		Message: fmt.Sprintf("Starting BLOB transfer. Size: %d bytes.", blobSize),
		BlobSize: blobSize,
		BlobPath: serverBlobPath,
		Value: metadata, 
	})
	
	// 2. Stream file data
	file, err := os.Open(serverBlobPath)
	if err != nil {
		log.Printf("%s BLOB_FILE_ERROR OP: GETBLOB Key: %s Filename: %s Error: Failed to open file: %v", logPrefix, req.Key, serverBlobPath, err)
		return 
	}
	defer file.Close()
	
	log.Printf("%s BLOB_TRANSFER_START OP: GETBLOB Key: %s Filename: %s streaming %d bytes to client.", logPrefix, req.Key, serverBlobPath, blobSize)
	n, err := io.Copy(conn, file)
	
	if err != nil {
		log.Printf("%s BLOB_TRANSFER_ERROR OP: GETBLOB Key: %s Error: Stream failed after %d bytes: %v", logPrefix, req.Key, n, err)
	} else if n != blobSize {
		log.Printf("%s BLOB_TRANSFER_ERROR OP: GETBLOB Key: %s Error: Stream size mismatch, expected %d, transferred %d", logPrefix, req.Key, blobSize, n)
	} else {
		log.Printf("%s OP_SUCCESS OP: GETBLOB Key: %s Filename: %s Transfer complete.", logPrefix, req.Key, serverBlobPath)
	}
}


// --- Persistence Commands (Server Side) ---

func handleDumpRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	filename := req.Filename
	if filename == "" {
		filename = *dumpFilenamePtr
	}
	
	// Use "CLIENT" as the source for client-triggered dump
	if err := dumpToFile(filename, "CLIENT"); err != nil {
		writeJSON(conn, Response{Status: "ERROR", Op: "DUMP", Message: fmt.Sprintf("Failed to dump data: %v", err)})
		log.Printf("%s OP_FAILURE OP: DUMP Filename: %s Error: %v", logPrefix, filename, err)
		return
	}
	writeJSON(conn, Response{Status: "OK", Op: "DUMP", Message: fmt.Sprintf("Data dumped to %s.", filename)})
	log.Printf("%s OP_SUCCESS OP: DUMP Filename: %s", logPrefix, filename)
}

func handleLoadRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	filename := req.Filename
	if filename == "" {
		writeJSON(conn, Response{Status: "ERROR", Op: "LOAD", Message: "Filename is required for LOAD."})
		log.Printf("%s OP_FAILURE OP: LOAD Error: Missing filename.", logPrefix)
		return
	}
	
	loadStoreFromFile(filename) 
	
	db.Lock.RLock()
	count := len(db.Store)
	db.Lock.RUnlock()
	
	writeJSON(conn, Response{
		Status: "OK", 
		Op: "LOAD", 
		Message: fmt.Sprintf("Load operation attempted on %s. Data was MERGED (updated existing keys and added new keys). Total store size: %d.", filename, count),
	})
	log.Printf("%s OP_SUCCESS OP: LOAD Filename: %s Total keys: %d", logPrefix, filename, count)
}


// --- Core CRUD, Search, and Bulk Delete (Server Side) ---

func handleRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	op := strings.ToUpper(req.Op)
	
	switch op {
	case "SET":
		if req.Key == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for SET."})
			log.Printf("%s OP_FAILURE OP: SET Key: (empty) Error: Missing key.", logPrefix)
			return
		}
		db.Lock.Lock()
		db.Store[req.Key] = req.Value
		db.Lock.Unlock()
		writeJSON(conn, Response{Status: "OK", Op: "SET", Key: req.Key, Message: "Key set successfully."})
		log.Printf("%s OP_SUCCESS OP: SET Key: %s", logPrefix, req.Key)

	case "GET":
		if req.Key == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for GET."})
			log.Printf("%s OP_FAILURE OP: GET Key: (empty) Error: Missing key.", logPrefix)
			return
		}
		db.Lock.RLock()
		value, ok := db.Store[req.Key]
		db.Lock.RUnlock()
		if !ok {
			writeJSON(conn, Response{Status: "NOT_FOUND", Op: "GET", Key: req.Key, Message: "Key not found."})
			log.Printf("%s OP_FAILURE OP: GET Key: %s Status: NOT_FOUND.", logPrefix, req.Key)
			return
		}
		writeJSON(conn, Response{Status: "OK", Op: "GET", Key: req.Key, Value: value})
		log.Printf("%s OP_SUCCESS OP: GET Key: %s", logPrefix, req.Key)

	case "DELETE":
		if req.Key == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for DELETE."})
			log.Printf("%s OP_FAILURE OP: DELETE Key: (empty) Error: Missing key.", logPrefix)
			return
		}
		
		db.Lock.Lock()
		value, ok := db.Store[req.Key]
		if ok {
			// Clean up BLOB file if the key points to one
			if metadata, isBlob := value.(map[string]interface{}); isBlob && metadata["type"] == "BLOB" {
				if path, pOK := metadata["path"].(string); pOK {
					if err := os.Remove(path); err != nil {
						log.Printf("%s BLOB_FILE_ERROR OP: DELETE Key: %s Filename: %s Error: Failed to delete BLOB file.", logPrefix, req.Key, path)
					} else {
						log.Printf("%s BLOB_FILE_DELETED OP: DELETE Key: %s Filename: %s", logPrefix, req.Key, path)
					}
				}
			}
			delete(db.Store, req.Key)
		}
		db.Lock.Unlock()

		if !ok {
			writeJSON(conn, Response{Status: "NOT_FOUND", Op: "DELETE", Key: req.Key, Message: "Key not found."})
			log.Printf("%s OP_FAILURE OP: DELETE Key: %s Status: NOT_FOUND.", logPrefix, req.Key)
			return
		}
		writeJSON(conn, Response{Status: "OK", Op: "DELETE", Key: req.Key, Message: "Key and associated BLOB (if present) deleted successfully."})
		log.Printf("%s OP_SUCCESS OP: DELETE Key: %s", logPrefix, req.Key)
	
	case "SEARCHKEY":
		if req.KeySubstring == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key substring is required for SEARCHKEY."})
			log.Printf("%s OP_FAILURE OP: SEARCHKEY Substring: (empty) Error: Missing substring.", logPrefix)
			return
		}
		
		db.Lock.RLock()
		defer db.Lock.RUnlock()
		
		results := make(map[string]interface{})
		substring := strings.ToLower(req.KeySubstring)
		
		for key, value := range db.Store {
			if strings.Contains(strings.ToLower(key), substring) {
				results[key] = value
			}
		}
		
		writeJSON(conn, Response{
			Status: "OK", 
			Op: "SEARCHKEY", 
			Message: fmt.Sprintf("Found %d keys containing '%s'.", len(results), req.KeySubstring),
			SearchResults: results,
		})
		log.Printf("%s OP_SUCCESS OP: SEARCHKEY Substring: %s Found: %d", logPrefix, req.KeySubstring, len(results))

	case "SEARCH": 
		if req.SearchValue == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Search value is required for SEARCH."})
			log.Printf("%s OP_FAILURE OP: SEARCH SearchValue: (empty) Error: Missing value.", logPrefix)
			return
		}
		
		db.Lock.RLock()
		defer db.Lock.RUnlock()

		results := make(map[string]interface{})
		searchTerm := strings.ToLower(req.SearchValue)
		
		for key, value := range db.Store {
			
			keyMatches := strings.Contains(strings.ToLower(key), searchTerm)
			
			valueMatches := false
			valueBytes, err := json.Marshal(value)
			if err == nil {
				valueStr := strings.ToLower(string(valueBytes))
				valueMatches = strings.Contains(valueStr, searchTerm)
			} else {
				valueMatches = strings.Contains(strings.ToLower(fmt.Sprintf("%v", value)), searchTerm)
			}
			
			if keyMatches || valueMatches {
				results[key] = value
			}
		}

		writeJSON(conn, Response{
			Status: "OK", 
			Op: "SEARCH", 
			Message: fmt.Sprintf("Found %d entries matching '%s' in key or value.", len(results), req.SearchValue),
			SearchResults: results,
		})
		log.Printf("%s OP_SUCCESS OP: SEARCH SearchValue: %s Found: %d", logPrefix, req.SearchValue, len(results))
		
	case "DELETEKEY":
		if req.KeySubstring == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key substring is required for DELETEKEY."})
			log.Printf("%s OP_FAILURE OP: DELETEKEY Substring: (empty) Error: Missing substring.", logPrefix)
			return
		}
		
		db.Lock.Lock()
		defer db.Lock.Unlock()
		
		substring := strings.ToLower(req.KeySubstring)
		deletedCount := 0
		keysToDelete := []string{}
		
		for key := range db.Store {
			if strings.Contains(strings.ToLower(key), substring) {
				keysToDelete = append(keysToDelete, key)
			}
		}
		
		for _, key := range keysToDelete {
			value := db.Store[key]
			// Clean up BLOB file if it exists
			if metadata, isBlob := value.(map[string]interface{}); isBlob && metadata["type"] == "BLOB" {
				if path, pOK := metadata["path"].(string); pOK {
					os.Remove(path) 
					log.Printf("%s BLOB_FILE_DELETED OP: DELETEKEY Key: %s Filename: %s", logPrefix, key, path)
				}
			}
			delete(db.Store, key)
			deletedCount++
		}
		
		writeJSON(conn, Response{
			Status: "OK", 
			Op: "DELETEKEY", 
			Message: fmt.Sprintf("Successfully deleted %d keys containing '%s' (and associated BLOB files).", deletedCount, req.KeySubstring),
			DeletedCount: deletedCount,
		})
		log.Printf("%s OP_SUCCESS OP: DELETEKEY Substring: %s Deleted: %d", logPrefix, req.KeySubstring, deletedCount)

	case "HELP":
		writeJSON(conn, Response{Status: "INFO", Op: "HELP", Message: "See shell output for commands."})
		log.Printf("%s OP_SUCCESS OP: HELP", logPrefix)

	default:
		writeJSON(conn, Response{Status: "ERROR", Message: "Unknown operation: " + req.Op})
		log.Printf("%s REQUEST_ERROR OP: %s Error: Unknown operation.", logPrefix, req.Op)
	}
}

func writeJSON(conn net.Conn, v interface{}) {
	encoder := json.NewEncoder(conn)
	encoder.SetIndent("", "") 
	if err := encoder.Encode(v); err != nil {
		log.Println("COMM_ERROR: Error sending response:", err)
	}
}

// ==========================================
//               CLIENT SHELL LOGIC
// ==========================================

// getDynamicClientTLSConfig uses the paths from the global dynamicConfig struct.
func getDynamicClientTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(dynamicConfig.CertPath, dynamicConfig.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate/key (%s, %s): %w", dynamicConfig.CertPath, dynamicConfig.KeyPath, err)
	}

	caCert, err := os.ReadFile(dynamicConfig.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate (%s): %w", dynamicConfig.CACertPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   dynamicConfig.Host, 
		MinVersion:   tls.VersionTLS12,
		InsecureSkipVerify: true, 
	}
	return config, nil
}

// connectToServer now uses getDynamicClientTLSConfig and dynamicConfig for connection details
func connectToServer() error {
	host := dynamicConfig.Host
	port := dynamicConfig.Port
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	log.Printf("CLIENT_ACTION: Attempting to connect to %s via mTLS...", addr)
	
	tlsConfig, err := getDynamicClientTLSConfig()
	if err != nil {
		log.Printf("CLIENT_ERROR: Failed to configure TLS client: %v", err)
		return fmt.Errorf("failed to configure TLS client: %w", err)
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		log.Printf("CLIENT_ERROR: Failed to connect via mTLS to %s: %v", addr, err)
		return fmt.Errorf("failed to connect via mTLS to %s: %w", addr, err)
	}
	
	if currentConn != nil {
		currentConn.Close()
	}

	currentConn = conn
	currentReader = bufio.NewReader(conn)
	
	// Read the initial server message (which now includes the ConnID and CN)
	rawResponse, err := currentReader.ReadString('\n')
	if err != nil {
		log.Printf("CLIENT_WARNING: Failed to read initial server message: %v", err)
	} else {
		// Attempt to parse the ID from the response for client display
		var resp Response
		if json.Unmarshal([]byte(rawResponse), &resp) == nil && resp.Status == "INFO" {
			fmt.Printf("Connection established to %s:%d (Client Cert: %s).\n", host, port, dynamicConfig.CertPath)
			fmt.Printf("Server INFO: %s\n", resp.Message)
		} else {
			fmt.Printf("Connection established to %s:%d (Client Cert: %s). Server sent raw response: %s\n", host, port, dynamicConfig.CertPath, rawResponse)
		}
	}
	
	log.Printf("CLIENT_CONNECT_SUCCESS: Connected to %s:%d", host, port)
	return nil
}

// disconnectServer explicitly closes the connection but keeps the shell running.
func disconnectServer() {
	if currentConn == nil {
		fmt.Println("Warning: Already disconnected.")
		return
	}
	
	currentConn.Close()
	currentConn = nil
	currentReader = nil
	fmt.Printf("Disconnected from %s:%d.\n", dynamicConfig.Host, dynamicConfig.Port)
	log.Printf("CLIENT_DISCONNECT_ACTION: Disconnected from %s:%d", dynamicConfig.Host, dynamicConfig.Port)
}

func runShell() {
	
	// Initial connection using the initial dynamicConfig
	if err := connectToServer(); err != nil {
		fmt.Printf("Initial connection failed: %v. Please use 'CONNECT ...' to establish a connection.\n", err)
	}

	shellReader := bufio.NewReader(os.Stdin)
	for {
		var prompt string
		if currentConn == nil {
			prompt = "[DISCONNECTED]> "
		} else {
			// Simplified prompt: host:port>
			prompt = fmt.Sprintf("%s:%d> ", dynamicConfig.Host, dynamicConfig.Port)
		}
		
		fmt.Print(prompt)
		
		input, _ := shellReader.ReadString('\n')
		input = strings.TrimSpace(input)

		op := strings.ToUpper(input)
		
		if op == "EXIT" || op == "QUIT" {
			fmt.Println("Exiting shell.")
			if currentConn != nil {
				currentConn.Close()
			}
			log.Printf("CLIENT_EXIT: Shell exited.")
			return
		}
		
		if op == "HELP" {
			printHelp()
			continue
		}
		
		// --- CONNECT Command Handler with Prefix Parsing ---
		if strings.HasPrefix(op, "CONNECT") {
			log.Printf("CLIENT_ACTION: CONNECT command received: %s", input)
			parts := strings.Fields(input)
			
			// Use current dynamicConfig as the baseline for updates
			newConfig := dynamicConfig
			
			// Use temporary variables to track connection updates
			tempHost := ""
			tempPort := 0
			
			// Iterate through all arguments starting from the second part (after "CONNECT")
			for i := 1; i < len(parts); i++ {
				arg := strings.ToLower(parts[i])
				
				switch arg {
				case "-h":
					if i+1 < len(parts) {
						tempHost = parts[i+1]
						i++ 
					} else {
						fmt.Println("Error: Missing host value after -h.")
						log.Printf("CLIENT_ERROR: CONNECT failed, missing host value.")
						goto connectLoopEnd
					}
				case "-p":
					if i+1 < len(parts) {
						p, err := strconv.Atoi(parts[i+1])
						if err != nil {
							fmt.Println("Error: Invalid port number after -p. Port must be numeric.")
							log.Printf("CLIENT_ERROR: CONNECT failed, invalid port value: %s", parts[i+1])
							goto connectLoopEnd
						}
						tempPort = p
						i++ 
					} else {
						fmt.Println("Error: Missing port value after -p.")
						log.Printf("CLIENT_ERROR: CONNECT failed, missing port value.")
						goto connectLoopEnd
					}
				case "-ca-cert":
					if i+1 < len(parts) {
						newConfig.CACertPath = parts[i+1]
						i++ 
					} else {
						fmt.Println("Error: Missing CA certificate path after -ca-cert.")
						log.Printf("CLIENT_ERROR: CONNECT failed, missing ca-cert path.")
						goto connectLoopEnd
					}
				case "-cert":
					if i+1 < len(parts) {
						newConfig.CertPath = parts[i+1]
						i++ 
					} else {
						fmt.Println("Error: Missing client certificate path after -cert.")
						log.Printf("CLIENT_ERROR: CONNECT failed, missing cert path.")
						goto connectLoopEnd
					}
				case "-key":
					if i+1 < len(parts) {
						newConfig.KeyPath = parts[i+1]
						i++ 
					} else {
						fmt.Println("Error: Missing client key path after -key.")
						log.Printf("CLIENT_ERROR: CONNECT failed, missing key path.")
						goto connectLoopEnd
					}
				default:
					// This catches any unknown flag or unexpected positional argument
					fmt.Printf("Error: Unknown argument or missing flag value '%s'. Use -h, -p, -ca-cert, -cert, -key flags.\n", parts[i])
					log.Printf("CLIENT_ERROR: CONNECT failed, unknown/misplaced argument: %s", parts[i])
					goto connectLoopEnd
				}
			}
			
			// Apply temp host/port values, only updating if they were explicitly provided in the command
			if tempHost != "" {
				newConfig.Host = tempHost
			}
			if tempPort != 0 {
				newConfig.Port = tempPort
			}

			// Final Check for a valid connection target
			if newConfig.Host == "" || newConfig.Port == 0 {
				fmt.Println("Error: Host (-h) and Port (-p) must be specified in the CONNECT command, or implicitly defined on launch.")
				log.Printf("CLIENT_ERROR: CONNECT failed, Host or Port missing after parsing.")
				goto connectLoopEnd
			}
			
			// Update the global dynamic configuration *before* connecting
			dynamicConfig = newConfig 
			
			if err := connectToServer(); err != nil {
				fmt.Println("Connection attempt failed:", err)
			}
			continue
			
			connectLoopEnd:
				continue
		}
		// --- END CONNECT Command Handler ---
		
		if op == "DISCONNECT" {
			disconnectServer()
			continue
		}
		
		if currentConn == nil {
			fmt.Println("Not connected. Use 'CONNECT ...' to establish a connection.")
			continue
		}
		
		req, err := parseShellInput(input)
		if err != nil {
			fmt.Println("Error:", err)
			log.Printf("CLIENT_INPUT_ERROR: Failed to parse shell input: %v", err)
			continue
		}
		
		rawResponse, err := sendRequestAndHandleBlob(req)
		
		if err != nil {
			if strings.Contains(err.Error(), "connection lost") {
				fmt.Println("Connection lost. Server disconnected unexpectedly.")
				log.Printf("CLIENT_COMM_ERROR: Connection lost to server during command: %s", req.Op)
				currentConn = nil
				currentReader = nil
				continue
			}
			
			fmt.Println("Communication Error:", err)
			log.Printf("CLIENT_COMM_ERROR: Communication error for command %s: %v", req.Op, err)
			continue
		}
		
		fmt.Println(rawResponse)
	}
}

// sendRequestAndHandleBlob sends the request and handles subsequent BLOB streaming (for PUTBLOB)
func sendRequestAndHandleBlob(req Request) (string, error) {
	if currentConn == nil || currentReader == nil {
		return "", fmt.Errorf("connection lost or not established")
	}
	
	reqJSON, _ := json.Marshal(req)
	
	// 1. Send Request
	_, err := currentConn.Write(append(reqJSON, '\n'))
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "closed network connection") {
			return "", fmt.Errorf("connection lost: Server disconnected.") 
		}
		return "", fmt.Errorf("failed to send request JSON: %w", err)
	}
	
	// 1.5. Handle BLOB Upload
	if strings.ToUpper(req.Op) == "PUTBLOB" {
		file, err := os.Open(req.ClientPath)
		if err != nil {
			return "", fmt.Errorf("failed to open client file for BLOB: %w", err)
		}
		defer file.Close()
		
		log.Printf("CLIENT_BLOB_UPLOAD_START: Key: %s, File: %s, Size: %d bytes.", req.Key, req.ClientPath, req.BlobSize)
		n, err := io.Copy(currentConn, file)
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "closed network connection") {
				return "", fmt.Errorf("connection lost during BLOB upload.")
			}
			log.Printf("CLIENT_BLOB_UPLOAD_ERROR: Key: %s, Error during stream: %v", req.Key, err)
			return "", fmt.Errorf("error during BLOB stream: %w", err)
		}
		if n != req.BlobSize {
			log.Printf("CLIENT_BLOB_UPLOAD_ERROR: Key: %s, Size mismatch: expected %d, sent %d", req.Key, req.BlobSize, n)
			return "", fmt.Errorf("BLOB stream size mismatch: expected %d, sent %d", req.BlobSize, n)
		}
		log.Printf("CLIENT_BLOB_UPLOAD_COMPLETE: Key: %s", req.Key)
	}
	
	// 2. Read Response
	rawResponse, err := currentReader.ReadString('\n')
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "closed network connection") {
			return "", fmt.Errorf("connection lost: Server disconnected while reading response.") 
		}
		return "", fmt.Errorf("error reading server response: %w", err)
	}
	
	var resp Response
	if err := json.Unmarshal([]byte(rawResponse), &resp); err != nil {
		return "", fmt.Errorf("error parsing server JSON response: %w", err)
	}

	// 2.5. Handle BLOB Download
	if strings.ToUpper(req.Op) == "GETBLOB" && resp.Status == "OK" && resp.BlobSize > 0 {
		return handleBlobRetrieval(resp)
	}
	
	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	return string(respJSON), nil
}

// handleBlobRetrieval streams the BLOB data from the server and saves it locally.
func handleBlobRetrieval(resp Response) (string, error) {
	if currentReader == nil {
		return "", fmt.Errorf("connection lost or not established")
	}
	
	originalName := filepath.Base(resp.BlobPath)
	if resp.Value != nil {
		if metadata, ok := resp.Value.(map[string]interface{}); ok {
			if on, ok := metadata["originalName"].(string); ok && on != "" {
				originalName = on
			}
		}
	}
	localPath := "retrieved_" + originalName

	file, err := os.Create(localPath)
	if err != nil {
		log.Printf("CLIENT_BLOB_DOWNLOAD_ERROR: Key: %s, Failed to create local file %s: %v", resp.Key, localPath, err)
		return "", fmt.Errorf("failed to create local file %s: %w", localPath, err)
	}
	defer file.Close()
	
	log.Printf("CLIENT_BLOB_DOWNLOAD_START: Key: %s, Size: %d bytes, saving to %s...", resp.Key, resp.BlobSize, localPath)
	
	n, err := io.CopyN(file, currentReader, resp.BlobSize)
	
	if err != nil && err != io.EOF {
		if strings.Contains(err.Error(), "closed network connection") {
			os.Remove(localPath)
			log.Printf("CLIENT_BLOB_DOWNLOAD_ERROR: Key: %s, Connection lost during download.", resp.Key)
			return "", fmt.Errorf("connection lost during BLOB download.")
		}
		os.Remove(localPath) 
		log.Printf("CLIENT_BLOB_DOWNLOAD_ERROR: Key: %s, Error during retrieval: %v", resp.Key, err)
		return "", fmt.Errorf("error during BLOB retrieval: %w", err)
	}
	
	if n != resp.BlobSize {
		os.Remove(localPath)
		log.Printf("CLIENT_BLOB_DOWNLOAD_ERROR: Key: %s, Size mismatch: expected %d, received %d", resp.Key, resp.BlobSize, n)
		return "", fmt.Errorf("BLOB size mismatch: expected %d, received %d", resp.BlobSize, n)
	}
	
	log.Printf("CLIENT_BLOB_DOWNLOAD_COMPLETE: Key: %s, Saved to %s", localPath)
	resp.Message = fmt.Sprintf("BLOB retrieved successfully. Saved to: %s", localPath)
	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	return string(respJSON), nil
}

// parseShellInput converts the raw shell command into a Request object.
func parseShellInput(input string) (Request, error) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return Request{}, fmt.Errorf("empty command")
	}

	op := strings.ToUpper(parts[0])
	req := Request{Op: op}

	switch op {
	case "SET":
		if len(parts) < 3 {
			return Request{}, fmt.Errorf("SET requires a key and a value. Usage: SET <key> <value/json>")
		}
		req.Key = parts[1]
		valueStr := strings.Join(parts[2:], " ")
		
		var value interface{}
		if json.Unmarshal([]byte(valueStr), &value) == nil {
			req.Value = value
		} else {
			req.Value = valueStr
		}
	case "GET", "DELETE", "GETBLOB", "DELETEBLOB":
		if len(parts) != 2 {
			return Request{}, fmt.Errorf("%s requires a key. Usage: %s <key>", op, op)
		}
		req.Key = parts[1]
		
	case "PUTBLOB": 
		if len(parts) != 3 {
			return Request{}, fmt.Errorf("PUTBLOB requires a key and a local file path. Usage: PUTBLOB <key> <local_file_path>")
		}
		req.Key = parts[1]
		req.ClientPath = parts[2]
		
		fileInfo, err := os.Stat(req.ClientPath)
		if os.IsNotExist(err) {
			return Request{}, fmt.Errorf("BLOB file not found: %s", req.ClientPath)
		}
		if err != nil {
			return Request{}, fmt.Errorf("error reading BLOB file info: %w", err)
		}
		if fileInfo.IsDir() {
			return Request{}, fmt.Errorf("BLOB file path is a directory")
		}
		req.BlobSize = fileInfo.Size()
		if req.BlobSize == 0 {
			return Request{}, fmt.Errorf("BLOB file is empty")
		}

	case "DUMP":
		if len(parts) > 2 {
			return Request{}, fmt.Errorf("DUMP takes 0 or 1 argument. Usage: DUMP [filename]")
		}
		if len(parts) == 2 {
			req.Filename = parts[1]
		}
	case "LOAD":
		if len(parts) != 2 {
			return Request{}, fmt.Errorf("LOAD requires a filename. Usage: LOAD <filename>")
		}
		req.Filename = parts[1]
	case "SEARCHKEY":
		if len(parts) != 2 {
			return Request{}, fmt.Errorf("SEARCHKEY requires a key substring. Usage: SEARCHKEY <substring>")
		}
		req.KeySubstring = parts[1]
	case "SEARCH":
		if len(parts) != 2 {
			return Request{}, fmt.Errorf("SEARCH requires a string. Usage: SEARCH <string>")
		}
		req.SearchValue = parts[1] 
	case "DELETEKEY":
		if len(parts) != 2 {
			return Request{}, fmt.Errorf("DELETEKEY requires a key substring. Usage: DELETEKEY <substring>")
		}
		req.KeySubstring = parts[1]
	case "HELP", "CONNECT", "DISCONNECT": // Shell commands are handled in runShell
	default:
		return Request{}, fmt.Errorf("unknown operation: %s", op)
	}
	return req, nil
}

func printHelp() {
	fmt.Println("\n--- Key-Value Data Store Commands (CRUD) ---")
	fmt.Println("SET <key> <value/json> - Set a key-value pair.")
	fmt.Println("GET <key>              - Retrieve the value for a key.")
	fmt.Println("DELETE <key>           - Remove a single key-value pair (removes associated BLOB if present).")
	
	fmt.Println("\n--- Binary Large Object (BLOB) Storage ---")
	fmt.Println("PUTBLOB <key> <file>   - Stores the local file as a BLOB under <key>.")
	fmt.Println("GETBLOB <key>          - Retrieves and saves the BLOB stored under <key> to a local file (saved as 'retrieved_<original_name>').")
	fmt.Println("DELETEBLOB <key>       - Explicitly remove a BLOB object and its file. Errors if key is not a BLOB.")

	fmt.Println("\n--- Search & Bulk Delete ---")
	fmt.Println("SEARCH <string>        - Find keys AND values containing the string (comprehensive search).")
	fmt.Println("SEARCHKEY <substring>  - Find keys containing the substring (key-only search).")
	fmt.Println("DELETEKEY <substring>  - DANGER: Delete ALL keys containing the substring (including BLOBs).")
	
	fmt.Println("\n--- System & Persistence & Connection ---")
	fmt.Printf("CONNECT -h <host> -p <port> [-ca-cert <path> -cert <path> -key <path>] - Connect or reconnect the shell.\n")
	fmt.Printf("    Current Target: %s:%d\n", dynamicConfig.Host, dynamicConfig.Port)
	fmt.Printf("    Current Client Cert: %s\n", dynamicConfig.CertPath)
	fmt.Printf("    Server Log File: %s (Server only, configurable via -log)\n", *logFilePtr)
	fmt.Printf("    Periodic Dump Interval (-dt): %s\n", *dtPtr)
	fmt.Println("DISCONNECT             - Close the current connection without exiting the shell.")
	fmt.Println("DUMP [filename]        - Trigger the server to dump the current database state to a file.")
	fmt.Println("LOAD <filename>        - Trigger the server to load data from file, MERGING/UPDATING existing keys and adding new ones.")
	fmt.Println("HELP                   - Show this help message.")
	fmt.Println("EXIT / QUIT            - Close the shell.")
	fmt.Println("--------------------------\n")
}