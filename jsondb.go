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
	"golang.org/x/crypto/bcrypt"
)

// --- Constants ---
const blobStorageDir = "blob_storage"
const defaultSecurityDumpFilename = "security_db_dump.json" 

// --- Permission Constants for RBAC/ACL ---
type Permission int

const (
	PermNone     Permission = iota // 0
	PermRead                       // 1 (GET, GETBLOB)
	PermWrite                      // 2 (SET, PUTBLOB)
	PermDelete                     // 3 (DELETE, DELETEBLOB, DELETEKEY on matching keys)
	PermAdmin                      // 4 (Full control, bypasses key-level checks)
)

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
	// Mode and Persistence Flags
	modePtr *string
	loadPtr *string
	dumpFilenamePtr *string
	securityDumpFilenamePtr *string
	logFilePtr *string
	dtPtr *time.Duration 

	// Connection Flags
	hostPtr *string
	portPtr *int

	// TLS Flags
	caCertPtr *string
	certPtr *string
	keyPtr *string
)

// --- Global Client State ---
var (
	currentConn net.Conn
	currentReader *bufio.Reader
	dynamicConfig ClientTLSConfig
	sessionToken string
	sessionUserID string
	clientCertCN string // Stores the Common Name of the client's mTLS certificate
)

// --- Core Data Structures (Updated/New) ---

// JSONDB remains the Key-Value store
type JSONDB struct {
	Store map[string]interface{}
	Lock  sync.RWMutex
}

// ACL defines permissions for a specific key
type ACL struct {
	UserPermissions  map[string]Permission `json:"userPermissions"`
	GroupPermissions map[string]Permission `json:"groupPermissions"`
	Default          Permission            `json:"default"`
}

// User structure
type User struct {
	ID       string `json:"id"`
	Password string `json:"password"` // Stored as bcrypt hash
	Groups   []string `json:"groups"`
}

// Group structure
type Group struct {
	ID      string `json:"id"`
	Members []string `json:"members"`
}

// Session structure (for authentication)
type Session struct {
	Token      string
	UserID     string
	ExpiryTime time.Time
}

// SecurityDB holds all application-level security data
type SecurityDB struct {
	Users    map[string]*User `json:"users"`
	Groups   map[string]*Group `json:"groups"`
	
	ACLStore map[string]ACL `json:"aclStore"`
	Sessions map[string]Session `json:"sessions"`
	Lock     sync.RWMutex
}

// SecurityDB_Persistent is used only for dumping/loading, excluding volatile data
type SecurityDB_Persistent struct {
	Users    map[string]*User `json:"users"`
	Groups   map[string]*Group `json:"groups"`
	ACLStore map[string]ACL `json:"aclStore"`
}

// --- Global Server State ---
var db = JSONDB{Store: make(map[string]interface{})}

var securityDB = SecurityDB{
	Users:    make(map[string]*User),
	Groups:   make(map[string]*Group),
	ACLStore: make(map[string]ACL),
	Sessions: make(map[string]Session),
}

// Atomic counter for unique connection IDs
var connectionCounter uint64

// --- Request/Response Structs ---
type Request struct {
	Op           string      `json:"op"`
	Key          string      `json:"key,omitempty"`
	Value        interface{} `json:"value,omitempty"`
	Filename     string      `json:"filename,omitempty"`
	SearchValue  string      `json:"searchValue,omitempty"`
	KeySubstring string     `json:"keySubstring,omitempty"`
	BlobSize     int64       `json:"blobSize,omitempty"`
	ClientPath   string      `json:"clientPath,omitempty"`

	// Fields for Authentication/Authorization
	Token        string      `json:"token,omitempty"`
	UserID       string      `json:"userId,omitempty"`
	Password     string      `json:"password,omitempty"`
	GroupName    string      `json:"groupName,omitempty"`
	Permission   int         `json:"permission,omitempty"`

	// Fields for RBAC/ACL Management
	ACLUserID    string      `json:"aclUserId,omitempty"`
	ACLGroupName string      `json:"aclGroupName,omitempty"`
	Groups       []string    `json:"groups,omitempty"`
	Members      []string    `json:"members,omitempty"`
}

type Response struct {
	Status        string                 `json:"status"`
	Op            string                 `json:"op,omitempty"`
	Message       string                 `json:"message,omitempty"`
	Key           string                 `json:"key,omitempty"`
	Value         interface{}            `json:"value,omitempty"`
	// CORRECTED: map<string>interface{} changed to map[string]interface{}
	SearchResults map[string]interface{} `json:"searchResults,omitempty"` 
	DeletedCount  int                    `json:"deletedCount,omitempty"`
	BlobSize      int64                  `json:"blobSize,omitempty"`
	BlobPath      string                 `json:"blobPath,omitempty"`

	// Fields for Authentication/Authorization
	Token         string      `json:"token,omitempty"`
	UserDetail    interface{} `json:"userDetail,omitempty"`
	ACLDetail     interface{} `json:"aclDetail,omitempty"`
	GroupDetail   interface{} `json:"groupDetail,omitempty"`
}


// ==========================================
//               LOGGING SETUP
// ==========================================

func setupFileLogger() {
	if *logFilePtr == "" {
		return
	}

	logFile, err := os.OpenFile(*logFilePtr, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", *logFilePtr, err)
	}

	multiWriter := io.MultiWriter(os.Stderr, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("SERVER_INFO: Logging initialized. Output directed to console and file: %s", *logFilePtr)
}

// ==========================================
//               PERSISTENCE LOGIC
// ==========================================

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
		db.Store[key] = value
		importedCount++
	}

	log.Printf("DATA_LOAD_SUCCESS: Successfully merged data from %s. Keys updated/added: %d. Total items now: %d", filename, importedCount, len(db.Store))
}

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

func dumpSecurityDB(source string) error {
	filename := *securityDumpFilenamePtr
	
	securityDB.Lock.RLock()
	persistentDB := SecurityDB_Persistent{
		Users: securityDB.Users,
		Groups: securityDB.Groups,
		ACLStore: securityDB.ACLStore,
	}
	data, err := json.MarshalIndent(persistentDB, "", "  ")
	securityDB.Lock.RUnlock()

	if err != nil {
		return fmt.Errorf("error marshalling security data: %w", err)
	}

	tmpFilename := filename + ".tmp"
	if err := os.WriteFile(tmpFilename, data, 0644); err != nil {
		return fmt.Errorf("error writing temporary security file: %w", err)
	}

	if err := os.Rename(tmpFilename, filename); err != nil {
		return fmt.Errorf("error renaming temporary security file: %w", err)
	}

	log.Printf("SECURITY_DUMP_SUCCESS: [%s] Security DB state successfully dumped to %s", source, filename)
	return nil
}

func loadSecurityDB() bool {
	filename := *securityDumpFilenamePtr
	
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("SECURITY_LOAD_FAIL: Security file not found: %s. Starting with default admin user.", filename)
			return false
		}
		log.Printf("SECURITY_LOAD_ERROR: Error reading security file %s: %v. Starting with default admin user.", filename, err)
		return false
	}

	securityDB.Lock.Lock()
	defer securityDB.Lock.Unlock()

	var persistentDB SecurityDB_Persistent
	if err := json.Unmarshal(data, &persistentDB); err != nil {
		log.Printf("SECURITY_LOAD_ERROR: Error unmarshalling security data from file %s: %v. Starting with default admin user.", filename, err)
		return false
	}

	securityDB.Users = persistentDB.Users
	securityDB.Groups = persistentDB.Groups
	securityDB.ACLStore = persistentDB.ACLStore

	log.Printf("SECURITY_LOAD_SUCCESS: Loaded %d users, %d groups, and %d ACLs from %s.", len(securityDB.Users), len(securityDB.Groups), len(securityDB.ACLStore), filename)
	return true
}

// ==========================================
//               SECURITY SETUP
// ==========================================

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func setupDefaultSecurity() {
	securityDB.Lock.Lock()
	defer securityDB.Lock.Unlock()

	if len(securityDB.Users) > 0 {
		return
	}

	hashedPassword, err := hashPassword("password")
	if err != nil {
		log.Fatalf("SECURITY_INIT_ERROR: Failed to hash default password: %v", err)
	}

	securityDB.Users["admin"] = &User{
		ID:       "admin",
		Password: hashedPassword, 
		Groups:   []string{"admin"},
	}

	securityDB.Groups["admin"] = &Group{
		ID:      "admin",
		Members: []string{"admin"},
	}

	securityDB.ACLStore["security_db"] = ACL{
		UserPermissions: map[string]Permission{"admin": PermAdmin},
		Default:         PermNone,
	}

	log.Printf("SECURITY_INIT: Default 'admin' user/group initialized. Password: 'password' (hashed). (Security DB was empty and not loaded)")
}

// ==========================================
//               INITIALIZATION
// ==========================================

// PrefixValue implements the flag.Value interface to handle both long and short forms
type PrefixValue struct {
	ptr *string
}

func (p *PrefixValue) String() string {
	if p.ptr == nil {
		return ""
	}
	return *p.ptr
}

func (p *PrefixValue) Set(s string) error {
	*p.ptr = s
	return nil
}

// PrefixIntValue implements the flag.Value interface for integer flags
type PrefixIntValue struct {
	ptr *int
}

func (p *PrefixIntValue) String() string {
	if p.ptr == nil {
		return "0"
	}
	return strconv.Itoa(*p.ptr)
}

func (p *PrefixIntValue) Set(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*p.ptr = v
	return nil
}

// PrefixDurationValue implements the flag.Value interface for duration flags
type PrefixDurationValue struct {
	ptr *time.Duration
}

func (p *PrefixDurationValue) String() string {
	if p.ptr == nil {
		return "0s"
	}
	return p.ptr.String()
}

func (p *PrefixDurationValue) Set(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*p.ptr = v
	return nil
}

func init() {
	// Determine default certs based on intended run mode for convenience
	defaultServerCert := "server.crt"
	defaultServerKey := "server.key"
	defaultClientCert := "client.crt"
	defaultClientKey := "client.key"
	
	// Create all flag pointers first
	modePtr = new(string)
	loadPtr = new(string)
	dumpFilenamePtr = new(string)
	securityDumpFilenamePtr = new(string)
	logFilePtr = new(string)
	dtPtr = new(time.Duration)
	hostPtr = new(string)
	portPtr = new(int)
	caCertPtr = new(string)
	certPtr = new(string)
	keyPtr = new(string)

	// Set Default Values
	*modePtr = "db"
	*dumpFilenamePtr = "store_dump.json"
	*securityDumpFilenamePtr = defaultSecurityDumpFilename
	*logFilePtr = "server.log"
	*dtPtr = 30 * time.Minute // 30m
	*hostPtr = "localhost"
	*portPtr = 9999
	*caCertPtr = "ca.crt"

	// Define all flags using flag.Var for custom handling to allow single-dash prefixes
	
	// MODE FLAG (Determines the default cert/key path dynamically for help/init)
	flag.Var(&PrefixValue{modePtr}, "s", "Server mode: 'db' (run server) or 'shell' (run client shell). Default: db")
	flag.Var(&PrefixValue{modePtr}, "mode", "Server mode: 'db' (run server) or 'shell' (run client shell). Default: db")

	// Adjust default cert/key based on mode before registering other flags for clearer help text
	isShell := false
	for _, arg := range os.Args {
		if strings.Contains(arg, "-s=shell") || strings.Contains(arg, "--s=shell") || strings.Contains(arg, "-mode=shell") || strings.Contains(arg, "--mode=shell") {
			isShell = true
			break
		}
	}

	if isShell {
		*certPtr = defaultClientCert
		*keyPtr = defaultClientKey
	} else {
		*certPtr = defaultServerCert
		*keyPtr = defaultServerKey
	}
	
	// PERSISTENCE FLAGS
	flag.Var(&PrefixValue{loadPtr}, "l", "Load initial data from this file (defaults to --df if not set). Default: ''")
	flag.Var(&PrefixValue{loadPtr}, "load", "Load initial data from this file (defaults to --df if not set). Default: ''")
	
	flag.Var(&PrefixValue{dumpFilenamePtr}, "df", "Default filename for data persistence dumps. Default: store_dump.json")
	flag.Var(&PrefixValue{dumpFilenamePtr}, "dump-file", "Default filename for data persistence dumps. Default: store_dump.json")

	flag.Var(&PrefixValue{securityDumpFilenamePtr}, "sdf", "Filename for security persistence dumps (Users, Groups, ACLs). Default: security_db_dump.json")
	flag.Var(&PrefixValue{securityDumpFilenamePtr}, "security-dump-file", "Filename for security persistence dumps (Users, Groups, ACLs). Default: security_db_dump.json")
	
	flag.Var(&PrefixValue{logFilePtr}, "log", "Path to the log file (server only). Set to '' to disable file logging. Default: server.log")
	
	flag.Var(&PrefixDurationValue{dtPtr}, "dt", "Duration for periodical persistence dump (e.g., 30m, 1h0s). If 0, no periodic dump. Default: 30m")
	flag.Var(&PrefixDurationValue{dtPtr}, "dump-time", "Duration for periodical persistence dump (e.g., 30m, 1h0s). If 0, no periodic dump. Default: 30m")


	// CONNECTION FLAGS
	flag.Var(&PrefixValue{hostPtr}, "h", "The host interface or address. Default: localhost")
	flag.Var(&PrefixValue{hostPtr}, "host", "The host interface or address. Default: localhost")
	
	flag.Var(&PrefixIntValue{portPtr}, "p", "The port number. Default: 9999")
	flag.Var(&PrefixIntValue{portPtr}, "port", "The port number. Default: 9999")

	// TLS FLAGS
	flag.Var(&PrefixValue{caCertPtr}, "ca", "Path to the root CA certificate. Default: ca.crt")
	flag.Var(&PrefixValue{caCertPtr}, "ca-cert", "Path to the root CA certificate. Default: ca.crt")

	flag.Var(&PrefixValue{certPtr}, "c", fmt.Sprintf("Path to the component's certificate. Default: %s", *certPtr))
	flag.Var(&PrefixValue{certPtr}, "cert", fmt.Sprintf("Path to the component's certificate. Default: %s", *certPtr))
	
	flag.Var(&PrefixValue{keyPtr}, "k", fmt.Sprintf("Path to the component's private key. Default: %s", *keyPtr))
	flag.Var(&PrefixValue{keyPtr}, "key", fmt.Sprintf("Path to the component's private key. Default: %s", *keyPtr))


	// Custom usage function to display all prefixes and variables
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s [options]:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Run mode: -s=<mode> or --mode=<mode>\n")
		fmt.Fprintf(os.Stderr, "  Connection: -h=<host> -p=<port> or --host=<host> --port=<port>\n")
		fmt.Fprintf(os.Stderr, "  TLS: -ca=<path> -c=<path> -k=<path> or --ca-cert=<path> --cert=<path> --key=<path>\n")
		fmt.Fprintf(os.Stderr, "\nAvailable Flags (Prefixes: single-dash short form, double-dash long form):\n")
		flag.PrintDefaults()
		
		fmt.Println("\nExample: Starting server with custom dump file and disabled periodic dump:")
		fmt.Println("  ./db_server -s db -df my_dump.json -dt 0s")
		
		fmt.Println("\nExample: Starting client shell connecting to remote host:")
		fmt.Println("  ./db_server -s shell -h remote.example.com -p 8080 -c remote_client.crt -k remote_client.key")
	}

	flag.Parse()
	
	// Re-assign loadPtr default if not explicitly set
	if *loadPtr == "" {
		*loadPtr = *dumpFilenamePtr
	}
}

// --- Main Entry Point ---

func main() {
	setupFileLogger()

	if *modePtr == "db" && (*certPtr == "" || *keyPtr == "") {
		log.Fatalf("CONFIG_ERROR: TLS mode requires -c/--cert and -k/--key flags to be set for the server.")
	}
	if *modePtr == "shell" && (*certPtr == "" || *keyPtr == "") {
		log.Fatalf("CONFIG_ERROR: TLS mode requires -c/--cert and -k/--key flags to be set for the client.")
	}

	addr := net.JoinHostPort(*hostPtr, strconv.Itoa(*portPtr))

	switch *modePtr {
	case "db":
		log.Printf("SERVER_START: Running in DB mode.")

		if err := os.MkdirAll(blobStorageDir, 0755); err != nil {
			log.Fatalf("CONFIG_ERROR: Failed to create BLOB storage directory '%s': %v", blobStorageDir, err)
		}

		defer func() {
			if r := recover(); r != nil {
				log.Printf("CRITICAL_PANIC: Panic detected: %v. Attempting emergency persistence dump.", r)
				if err := dumpToFile(*dumpFilenamePtr, "CRASH"); err != nil {
					log.Printf("EMERGENCY_DATA_DUMP_FAILED: Data store dump failed: %v", err)
				}
				if err := dumpSecurityDB("CRASH"); err != nil { 
					log.Printf("EMERGENCY_SECURITY_DUMP_FAILED: Security DB dump failed: %v", err)
				}
				panic(r)
			}
		}()

		loadSecurityDB()
		setupDefaultSecurity() 

		loadStoreFromFile(*loadPtr)

		runServer(addr)

	case "shell":
		log.Printf("CLIENT_START: Running in Shell mode.")
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
		fmt.Println("Error: You must specify a mode using -s or --mode.")
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

func StartDumpScheduler() *time.Ticker {
	duration := *dtPtr
	
	if duration <= 0 {
		log.Println("SCHEDULER_INFO: Periodic persistence disabled (dt=0 or negative).")
		return nil
	}

	if duration < 10*time.Second {
		duration = 10 * time.Second
		log.Printf("SCHEDULER_WARNING: Dump interval too short. Setting minimum to %s.", duration)
	}

	ticker := time.NewTicker(duration)
	log.Printf("SCHEDULER_START: Periodic persistence enabled. Dumping every %s to %s and %s", duration, *dumpFilenamePtr, *securityDumpFilenamePtr)

	go func() {
		for range ticker.C {
			if err := dumpToFile(*dumpFilenamePtr, "PERIODIC"); err != nil {
				log.Printf("SCHEDULER_DATA_DUMP_FAILED: Data dump failed: %v", err)
			}
			if err := dumpSecurityDB("PERIODIC"); err != nil {
				log.Printf("SCHEDULER_SECURITY_DUMP_FAILED: Security DB dump failed: %v", err)
			}
		}
	}()
	return ticker
}

// --- Security and ACL Logic (Server Side) ---

func generateToken(userID string) string {
	return fmt.Sprintf("%s-%d", userID, time.Now().UnixNano())
}

func checkPermission(userID string, key string) Permission {
	securityDB.Lock.RLock()
	defer securityDB.Lock.RUnlock()

	user, userExists := securityDB.Users[userID]
	if !userExists {
		return PermNone
	}

	// 1. Check for Admin Permission (Bypass all checks)
	acl, aclExists := securityDB.ACLStore["security_db"]
	if aclExists {
		if p, ok := acl.UserPermissions[userID]; ok && p == PermAdmin {
			return PermAdmin
		}
		for _, groupID := range user.Groups {
			if p, ok := acl.GroupPermissions[groupID]; ok && p == PermAdmin {
				return PermAdmin
			}
		}
	}

	// 2. Check Key-Specific ACL
	keyACL, keyACLExists := securityDB.ACLStore[key]
	if !keyACLExists {
		return PermNone
	}

	// 3. Check Direct User Permission
	maxPerm := keyACL.Default
	if p, ok := keyACL.UserPermissions[userID]; ok && p > maxPerm {
		maxPerm = p
	}

	// 4. Check Group Permissions (Return highest group permission)
	for _, groupID := range user.Groups {
		if p, ok := keyACL.GroupPermissions[groupID]; ok && p > maxPerm {
			maxPerm = p
		}
	}

	return maxPerm
}

func authenticateSession(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("session token missing")
	}

	securityDB.Lock.RLock()
	defer securityDB.Lock.RUnlock()

	session, ok := securityDB.Sessions[token]
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	if time.Now().After(session.ExpiryTime) {
		log.Printf("SESSION_EXPIRED: Token for user %s expired. User ID: %s", session.UserID, session.UserID)
		return "", fmt.Errorf("session expired, please login again")
	}

	return session.UserID, nil
}

// --- Authentication and ACL Management Functions (Server Side) ---

func handleAuthAndACLRequest(conn net.Conn, req Request, clientCN string, logPrefix string) {
	op := strings.ToUpper(req.Op)

	switch op {
	case "LOGIN":
		if req.UserID == "" || req.Password == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "User ID and Password are required."})
			return
		}

		securityDB.Lock.RLock()
		userPtr, ok := securityDB.Users[req.UserID]
		securityDB.Lock.RUnlock()
		
		if !ok || !checkPasswordHash(req.Password, userPtr.Password) {
			writeJSON(conn, Response{Status: "AUTH_FAIL", Message: "Invalid credentials."})
			log.Printf("%s AUTH_FAIL OP: LOGIN User: %s", logPrefix, req.UserID)
			return
		}

		token := generateToken(req.UserID)
		expiry := time.Now().Add(1 * time.Hour)

		securityDB.Lock.Lock()
		securityDB.Sessions[token] = Session{Token: token, UserID: req.UserID, ExpiryTime: expiry}
		securityDB.Lock.Unlock()

		writeJSON(conn, Response{Status: "OK", Op: "LOGIN", Token: token, Message: fmt.Sprintf("Login successful. Token expires at %s", expiry.Format(time.RFC3339))})
		log.Printf("%s AUTH_SUCCESS OP: LOGIN User: %s Token: %s", logPrefix, req.UserID, token)

	case "LOGOUT":
		if req.Token == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Token is required for LOGOUT."})
			return
		}

		securityDB.Lock.Lock()
		if session, ok := securityDB.Sessions[req.Token]; ok {
			delete(securityDB.Sessions, req.Token)
			writeJSON(conn, Response{Status: "OK", Op: "LOGOUT", Message: fmt.Sprintf("User %s logged out successfully.", session.UserID)})
			log.Printf("%s AUTH_SUCCESS OP: LOGOUT User: %s", logPrefix, session.UserID)
		} else {
			writeJSON(conn, Response{Status: "ERROR", Op: "LOGOUT", Message: "Invalid or expired token."})
		}
		securityDB.Lock.Unlock()

	case "CREATEUSER", "DELETEUSER", "VIEWUSER", "CHANGEPASSWORD", "UPDATEUSER",
         "CREATEGROUP", "DELETEGROUP", "VIEWGROUP", "UPDATEGROUP", "ADDUSERTOGROUP", "REMOVEUSERFROMGROUP",
         "SETACL", "VIEWACL", "DELETEACL", "UPDATEACL", "SETPERM", "REMOVEPERM":

		userID, err := authenticateSession(req.Token)
		if err != nil {
			writeJSON(conn, Response{Status: "AUTH_FAIL", Message: fmt.Sprintf("Authentication failed: %v", err)})
			return
		}

		perm := checkPermission(userID, "security_db") 
		if perm < PermAdmin {
			writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Admin privileges required for security operations."})
			log.Printf("%s OP_REJECTED OP: %s User: %s", logPrefix, op, userID)
			return
		}

		securityDB.Lock.Lock()
		defer securityDB.Lock.Unlock()
		
		defer func() {
			if op != "VIEWUSER" && op != "VIEWGROUP" && op != "VIEWACL" {
				if err := dumpSecurityDB(op); err != nil {
					log.Printf("SECURITY_DUMP_FAILED after %s: %v", op, err)
				}
			}
		}()

		switch op {
		case "CREATEUSER":
			if req.UserID == "" || req.Password == "" {
				writeJSON(conn, Response{Status: "ERROR", Message: "User ID and Password required."})
				return
			}
			if _, ok := securityDB.Users[req.UserID]; ok {
				writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s already exists.", req.UserID)})
				return
			}
			hashedPassword, err := hashPassword(req.Password)
			if err != nil {
				writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Failed to process password: %v", err)})
				return
			}
			securityDB.Users[req.UserID] = &User{ID: req.UserID, Password: hashedPassword, Groups: []string{}} 
			writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("User %s created. (Password Hashed)", req.UserID)})
			log.Printf("%s OP_SUCCESS OP: CREATEUSER User: %s", logPrefix, req.UserID)
			
		case "DELETEUSER":
			if req.UserID == "" {
				writeJSON(conn, Response{Status: "ERROR", Message: "User ID required for DELETEUSER."})
				return
			}
			if _, ok := securityDB.Users[req.UserID]; !ok {
				writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s not found.", req.UserID)})
				return
			}
			
			for groupID := range securityDB.Groups {
				group := securityDB.Groups[groupID]
				group.Members = removeElement(group.Members, req.UserID)
			}
			
			for key, acl := range securityDB.ACLStore {
				if _, ok := acl.UserPermissions[req.UserID]; ok {
					delete(acl.UserPermissions, req.UserID)
					securityDB.ACLStore[key] = acl
				}
			}
			delete(securityDB.Users, req.UserID)
			
			for token, session := range securityDB.Sessions {
				if session.UserID == req.UserID {
					delete(securityDB.Sessions, token)
					log.Printf("%s SESSION_CLEANUP: Invalidated session for deleted user %s.", logPrefix, req.UserID)
				}
			}
			
			writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("User %s deleted and cleaned up from groups/ACLs/sessions.", req.UserID)})
			log.Printf("%s OP_SUCCESS OP: DELETEUSER User: %s", logPrefix, req.UserID)
			
		case "VIEWUSER":
			if req.UserID == "" {
				ids := make([]string, 0, len(securityDB.Users))
				for id := range securityDB.Users {
					ids = append(ids, id)
				}
				writeJSON(conn, Response{Status: "OK", UserDetail: ids, Message: fmt.Sprintf("Found %d users.", len(ids))})
				return
			}
			userPtr, ok := securityDB.Users[req.UserID]
			if !ok {
				writeJSON(conn, Response{Status: "NOT_FOUND", Message: fmt.Sprintf("User %s not found.", req.UserID)})
				return
			}
			safeUser := struct {
				ID string `json:"id"`
				Password string `json:"password"`
				Groups []string `json:"groups"`
			}{
				ID: userPtr.ID,
				Password: "<HIDDEN_HASH>",
				Groups: userPtr.Groups,
			}
			writeJSON(conn, Response{Status: "OK", UserDetail: safeUser})
			log.Printf("%s OP_SUCCESS OP: VIEWUSER User: %s", logPrefix, req.UserID)

        case "CHANGEPASSWORD":
            if req.UserID == "" || req.Password == "" {
                writeJSON(conn, Response{Status: "ERROR", Message: "User ID and New Password required."})
                return
            }
            userPtr, ok := securityDB.Users[req.UserID]
            if !ok {
                writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s not found.", req.UserID)})
                return
            }
            hashedPassword, err := hashPassword(req.Password)
            if err != nil {
                writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Failed to process password: %v", err)})
                return
            }
            userPtr.Password = hashedPassword
            writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("Password for user %s updated.", req.UserID)})
            log.Printf("%s OP_SUCCESS OP: CHANGEPASSWORD User: %s", logPrefix, req.UserID)

        case "UPDATEUSER":
            if req.UserID == "" || req.Groups == nil {
                writeJSON(conn, Response{Status: "ERROR", Message: "User ID and Group list required (e.g., -groups group1,group2)."})
                return
            }
            userPtr, ok := securityDB.Users[req.UserID]
            if !ok {
                writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s not found.", req.UserID)})
                return
            }
            
            for _, groupID := range req.Groups {
                if _, ok := securityDB.Groups[groupID]; !ok {
                    writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Group %s does not exist. Update aborted.", groupID)})
                    return
                }
            }

            userPtr.Groups = req.Groups 
            
            writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("Groups for user %s updated to: %v. (Note: Group membership lists must be manually synced or rely on ADD/REMOVE commands)", req.UserID, req.Groups)})
            log.Printf("%s OP_SUCCESS OP: UPDATEUSER User: %s Groups: %v", logPrefix, req.UserID, req.Groups)

		case "CREATEGROUP":
			if req.GroupName == "" {
				writeJSON(conn, Response{Status: "ERROR", Message: "Group name required."})
				return
			}
			if _, ok := securityDB.Groups[req.GroupName]; ok {
				writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Group %s already exists.", req.GroupName)})
				return
			}
			securityDB.Groups[req.GroupName] = &Group{ID: req.GroupName, Members: []string{}} 
			writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("Group %s created.", req.GroupName)})
			log.Printf("%s OP_SUCCESS OP: CREATEGROUP Group: %s", logPrefix, req.GroupName)
			
		case "DELETEGROUP":
			if req.GroupName == "" {
				writeJSON(conn, Response{Status: "ERROR", Message: "Group name required for DELETEGROUP."})
				return
			}
			if _, ok := securityDB.Groups[req.GroupName]; !ok {
				writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Group %s not found.", req.GroupName)})
				return
			}
			
			for userID := range securityDB.Users {
				user := securityDB.Users[userID]
				user.Groups = removeElement(user.Groups, req.GroupName)
			}
			
			for key, acl := range securityDB.ACLStore {
				if _, ok := acl.GroupPermissions[req.GroupName]; ok {
					delete(acl.GroupPermissions, req.GroupName)
					securityDB.ACLStore[key] = acl
				}
			}
			delete(securityDB.Groups, req.GroupName)
			
			writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("Group %s deleted and cleaned up from users/ACLs.", req.GroupName)})
			log.Printf("%s OP_SUCCESS OP: DELETEGROUP Group: %s", logPrefix, req.GroupName)
			
		case "VIEWGROUP":
			if req.GroupName == "" {
				ids := make([]string, 0, len(securityDB.Groups))
				for id := range securityDB.Groups {
					ids = append(ids, id)
				}
				writeJSON(conn, Response{Status: "OK", GroupDetail: ids, Message: fmt.Sprintf("Found %d groups.", len(ids))})
				return
			}
			groupPtr, ok := securityDB.Groups[req.GroupName]
			if !ok {
				writeJSON(conn, Response{Status: "NOT_FOUND", Message: fmt.Sprintf("Group %s not found.", req.GroupName)})
				return
			}
			writeJSON(conn, Response{Status: "OK", GroupDetail: *groupPtr})
			log.Printf("%s OP_SUCCESS OP: VIEWGROUP Group: %s", logPrefix, req.GroupName)

        case "UPDATEGROUP":
            if req.GroupName == "" || req.Members == nil {
                writeJSON(conn, Response{Status: "ERROR", Message: "Group Name and Member list required (e.g., -members user1,user2)."})
                return
            }
            groupPtr, ok := securityDB.Groups[req.GroupName]
            if !ok {
                writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Group %s not found.", req.GroupName)})
                return
            }

            for _, userID := range req.Members {
                if _, ok := securityDB.Users[userID]; !ok {
                    writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s does not exist. Update aborted.", userID)})
                    return
                }
            }
            
            currentMembersMap := make(map[string]bool)
            for _, memberID := range groupPtr.Members {
                currentMembersMap[memberID] = true
            }

            newMembersMap := make(map[string]bool)
            for _, memberID := range req.Members {
                newMembersMap[memberID] = true
            }
            
            for memberID := range currentMembersMap {
                if !newMembersMap[memberID] {
                    if userPtr, ok := securityDB.Users[memberID]; ok {
                        userPtr.Groups = removeElement(userPtr.Groups, req.GroupName)
                    }
                }
            }

            for memberID := range newMembersMap {
                if !currentMembersMap[memberID] {
                    if userPtr, ok := securityDB.Users[memberID]; ok {
                        userPtr.Groups = append(userPtr.Groups, req.GroupName)
                    }
                }
            }

            groupPtr.Members = req.Members

            writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("Members for group %s updated to: %v. All affected users updated.", req.GroupName, req.Members)})
            log.Printf("%s OP_SUCCESS OP: UPDATEGROUP Group: %s Members: %v", logPrefix, req.GroupName, req.Members)

        case "ADDUSERTOGROUP":
            if req.UserID == "" || req.GroupName == "" {
                writeJSON(conn, Response{Status: "ERROR", Message: "User ID and Group Name required."})
                return
            }
            userPtr, uOk := securityDB.Users[req.UserID]
            groupPtr, gOk := securityDB.Groups[req.GroupName]
            if !uOk {
                writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s not found.", req.UserID)})
                return
            }
            if !gOk {
                writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Group %s not found.", req.GroupName)})
                return
            }

            if contains(userPtr.Groups, req.GroupName) {
                writeJSON(conn, Response{Status: "INFO", Message: fmt.Sprintf("User %s is already in group %s.", req.UserID, req.GroupName)})
                return
            }
            
            userPtr.Groups = append(userPtr.Groups, req.GroupName)
            groupPtr.Members = append(groupPtr.Members, req.UserID)

            writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("User %s added to group %s.", req.UserID, req.GroupName)})
            log.Printf("%s OP_SUCCESS OP: ADDUSERTOGROUP User: %s Group: %s", logPrefix, req.UserID, req.GroupName)

        case "REMOVEUSERFROMGROUP":
            if req.UserID == "" || req.GroupName == "" {
                writeJSON(conn, Response{Status: "ERROR", Message: "User ID and Group Name required."})
                return
            }
            userPtr, uOk := securityDB.Users[req.UserID]
            groupPtr, gOk := securityDB.Groups[req.GroupName]
            if !uOk || !gOk {
                writeJSON(conn, Response{Status: "ERROR", Message: "User or Group not found."})
                return
            }

            if !contains(userPtr.Groups, req.GroupName) {
                writeJSON(conn, Response{Status: "INFO", Message: fmt.Sprintf("User %s is not in group %s.", req.UserID, req.GroupName)})
                return
            }
            
            userPtr.Groups = removeElement(userPtr.Groups, req.GroupName)
            groupPtr.Members = removeElement(groupPtr.Members, req.UserID)

            writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("User %s removed from group %s.", req.UserID, req.GroupName)})
            log.Printf("%s OP_SUCCESS OP: REMOVEUSERFROMGROUP User: %s Group: %s", logPrefix, req.UserID, req.GroupName)


		case "SETACL", "SETPERM":
			if req.Key == "" || (req.ACLUserID == "" && req.ACLGroupName == "") {
				writeJSON(conn, Response{Status: "ERROR", Message: "Key and ACLUserID or ACLGroupName required."})
				return
			}
			perm := Permission(req.Permission)
			if perm < PermNone || perm > PermAdmin {
				writeJSON(conn, Response{Status: "ERROR", Message: "Invalid permission level (0-4)."})
				return
			}

			acl := securityDB.ACLStore[req.Key]
			if acl.UserPermissions == nil {
				acl.UserPermissions = make(map[string]Permission)
			}
			if acl.GroupPermissions == nil {
				acl.GroupPermissions = make(map[string]Permission)
			}

			message := ""
			if req.ACLUserID != "" {
				if _, ok := securityDB.Users[req.ACLUserID]; !ok {
					writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("User %s does not exist. Cannot set ACL.", req.ACLUserID)})
					return
				}
				acl.UserPermissions[req.ACLUserID] = perm
				message = fmt.Sprintf("ACL set for Key: %s, User: %s, Permission: %d.", req.Key, req.ACLUserID, perm)
			} else if req.ACLGroupName != "" {
				if _, ok := securityDB.Groups[req.ACLGroupName]; !ok {
					writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("Group %s does not exist. Cannot set ACL.", req.ACLGroupName)})
					return
				}
				acl.GroupPermissions[req.ACLGroupName] = perm
				message = fmt.Sprintf("ACL set for Key: %s, Group: %s, Permission: %d.", req.Key, req.ACLGroupName, perm)
			}

			securityDB.ACLStore[req.Key] = acl
			writeJSON(conn, Response{Status: "OK", Message: message})
			log.Printf("%s OP_SUCCESS OP: %s Key: %s", logPrefix, op, req.Key)
			
        case "REMOVEPERM":
			if req.Key == "" || (req.ACLUserID == "" && req.ACLGroupName == "") {
				writeJSON(conn, Response{Status: "ERROR", Message: "Key and ACLUserID or ACLGroupName required."})
				return
			}
            
			acl, aclExists := securityDB.ACLStore[req.Key]
            if !aclExists {
                writeJSON(conn, Response{Status: "INFO", Message: fmt.Sprintf("No explicit ACL found for key %s.", req.Key)})
                return
            }

			message := ""
			removed := false
			if req.ACLUserID != "" {
				if _, ok := acl.UserPermissions[req.ACLUserID]; ok {
					delete(acl.UserPermissions, req.ACLUserID)
					removed = true
					message = fmt.Sprintf("User %s removed from ACL for Key: %s.", req.ACLUserID, req.Key)
				}
			} else if req.ACLGroupName != "" {
				if _, ok := acl.GroupPermissions[req.ACLGroupName]; ok {
					delete(acl.GroupPermissions, req.ACLGroupName)
					removed = true
					message = fmt.Sprintf("Group %s removed from ACL for Key: %s.", req.ACLGroupName, req.Key)
				}
			}
            
            if removed {
                if len(acl.UserPermissions) == 0 && len(acl.GroupPermissions) == 0 && acl.Default == PermNone {
                    delete(securityDB.ACLStore, req.Key)
                    message += " The entire ACL object was removed."
                } else {
                    securityDB.ACLStore[req.Key] = acl
                }
                writeJSON(conn, Response{Status: "OK", Message: message})
                log.Printf("%s OP_SUCCESS OP: REMOVEPERM Key: %s", logPrefix, req.Key)
            } else {
                writeJSON(conn, Response{Status: "INFO", Message: "User/Group was not explicitly listed in the ACL."})
            }
            
        case "UPDATEACL":
            if req.Key == "" {
                 writeJSON(conn, Response{Status: "ERROR", Message: "Key and valid Default Permission (0-4) required."})
                return
            }
            if req.Permission < 0 || req.Permission > 4 {
                writeJSON(conn, Response{Status: "ERROR", Message: "Invalid Default Permission (0-4) required."})
                return
            }
            
            acl := securityDB.ACLStore[req.Key]
            acl.Default = Permission(req.Permission)
            securityDB.ACLStore[req.Key] = acl
            
            writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("Default permission for ACL key %s set to %d.", req.Key, req.Permission)})
            log.Printf("%s OP_SUCCESS OP: UPDATEACL Key: %s DefaultPerm: %d", logPrefix, req.Key, req.Permission)

		case "VIEWACL":
			if req.Key == "" {
				keys := make([]string, 0, len(securityDB.ACLStore))
				for key := range securityDB.ACLStore {
					keys = append(keys, key)
				}
				writeJSON(conn, Response{Status: "OK", ACLDetail: keys, Message: fmt.Sprintf("Found %d keys with explicit ACLs.", len(keys))})
				return
			}
			acl, ok := securityDB.ACLStore[req.Key]
			if !ok {
				writeJSON(conn, Response{Status: "NOT_FOUND", Message: fmt.Sprintf("No explicit ACL found for key %s. Default permission is %d.", req.Key, PermNone)})
				return
			}
			writeJSON(conn, Response{Status: "OK", ACLDetail: acl})
			log.Printf("%s OP_SUCCESS OP: VIEWACL Key: %s", logPrefix, req.Key)
			
		case "DELETEACL":
			if req.Key == "" {
				writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for DELETEACL."})
				return
			}
			if _, ok := securityDB.ACLStore[req.Key]; !ok {
				writeJSON(conn, Response{Status: "ERROR", Message: fmt.Sprintf("No explicit ACL found for key %s.", req.Key)})
				return
			}
			delete(securityDB.ACLStore, req.Key)
			writeJSON(conn, Response{Status: "OK", Message: fmt.Sprintf("ACL deleted for key %s.", req.Key)})
			log.Printf("%s OP_SUCCESS OP: DELETEACL Key: %s", logPrefix, req.Key)

		}
	}
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

func removeElement(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func runServer(addr string) {
	ticker := StartDumpScheduler()
	if ticker != nil {
		defer ticker.Stop()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("SERVER_SHUTDOWN_INITIATED: Received signal %v. Initiating mandatory graceful persistence dump...", sig)
		if err := dumpToFile(*dumpFilenamePtr, "SHUTDOWN"); err != nil {
			log.Printf("SERVER_SHUTDOWN_ERROR: Data dump FAILED: %v", err)
		}
		if err := dumpSecurityDB("SHUTDOWN"); err != nil { 
			log.Printf("SERVER_SHUTDOWN_ERROR: Security DB dump FAILED: %v", err)
		}
		log.Println("SERVER_SHUTDOWN_COMPLETE: Persistence successful. Shutting down server.")
		os.Exit(0)
	}()

	tlsConfig, err := getServerTLSConfig()
	if err != nil {
		log.Fatalf("CONFIG_ERROR: Failed to configure TLS server: %v", err)
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Printf("SERVER_INFO: JSON DB Server running on %s in mTLS Mode (Data Dump: %s, Security Dump: %s)", addr, *dumpFilenamePtr, *securityDumpFilenamePtr)
	log.Printf("SERVER_INFO: Application-level authentication is now REQUIRED via LOGIN command.")

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
	connID := atomic.AddUint64(&connectionCounter, 1)
	defer conn.Close()
	clientCN := "UNKNOWN"
	remoteAddr := conn.RemoteAddr().String()
	clientIP, clientPort, _ := net.SplitHostPort(remoteAddr)
	logPrefix := fmt.Sprintf("[ConnID:%d:%s][%s:%s]", connID, clientCN, clientIP, clientPort)

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err == nil {
			if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
				clientCN = tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
			}
			logPrefix = fmt.Sprintf("[ConnID:%d:%s][%s:%s]", connID, clientCN, clientIP, clientPort)
		} else {
			log.Printf("[ConnID:%d:UNKNOWN][%s:%s] AUTH_REJECTED Message: mTLS Handshake Failed: %v", connID, clientIP, clientPort, err)
			return
		}
	} else {
		log.Printf("[ConnID:%d:UNKNOWN][%s:%s] AUTH_REJECTED Message: Connection is not TLS. Closing.", connID, clientIP, clientPort)
		return
	}

	log.Printf("%s CONNECTION_OPEN (Authorized via mTLS)", logPrefix)
	initialMessage := fmt.Sprintf("Connected to JSON DB Server via mTLS. Your CN is [%s]. Application LOGIN is required for data operations.", clientCN)
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

		switch op {
		case "LOGIN", "LOGOUT", 
             "CREATEUSER", "DELETEUSER", "VIEWUSER", "CHANGEPASSWORD", "UPDATEUSER",
             "CREATEGROUP", "DELETEGROUP", "VIEWGROUP", "UPDATEGROUP", "ADDUSERTOGROUP", "REMOVEUSERFROMGROUP",
             "SETACL", "VIEWACL", "DELETEACL", "UPDATEACL", "SETPERM", "REMOVEPERM":
			handleAuthAndACLRequest(conn, req, clientCN, logPrefix)
			continue
		}

		userID, err := authenticateSession(req.Token)
		if err != nil {
			writeJSON(conn, Response{Status: "AUTH_FAIL", Message: fmt.Sprintf("Authentication required: %v", err)})
			continue
		}
		
		log.Printf("%s REQUEST_IN OP: %s Key: %s User: %s", logPrefix, op, req.Key, userID)

		switch op {
		case "PUTBLOB":
			handlePutBlobRequest(conn, req, userID, logPrefix)
		case "GETBLOB":
			handleGetBlobRequest(conn, req, userID, logPrefix)
		case "DELETEBLOB":
			handleDeleteBlobRequest(conn, req, userID, logPrefix)
		case "DUMP":
			handleDumpRequest(conn, req, userID, logPrefix)
		case "LOAD":
			handleLoadRequest(conn, req, userID, logPrefix)
		default:
			handleRequest(conn, req, userID, logPrefix)
		}
	}
	log.Printf("%s CONNECTION_CLOSED", logPrefix)
}

// --- BLOB Handling Functions (Server Side) ---

func handleDeleteBlobRequest(conn net.Conn, req Request, userID string, logPrefix string) {
	if req.Key == "" {
		writeJSON(conn, Response{Status: "ERROR", Op: "DELETEBLOB", Message: "Key is required for DELETEBLOB."})
		return
	}
	
	if perm := checkPermission(userID, req.Key); perm < PermDelete {
		writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Delete access required."})
		log.Printf("%s OP_REJECTED OP: DELETEBLOB Key: %s User: %s", logPrefix, req.Key, userID)
		return
	}

	db.Lock.Lock()
	defer db.Lock.Unlock()

	value, ok := db.Store[req.Key]
	if !ok {
		writeJSON(conn, Response{Status: "NOT_FOUND", Op: "DELETEBLOB", Key: req.Key, Message: "Key not found."})
		return
	}

	metadata, isBlob := value.(map[string]interface{})
	if !isBlob || metadata["type"] != "BLOB" {
		writeJSON(conn, Response{Status: "ERROR", Op: "DELETEBLOB", Key: req.Key, Message: "Key exists but is not a BLOB object. Use DELETE to remove."})
		return
	}

	path, pOK := metadata["path"].(string)
	if pOK && path != "" {
		if err := os.Remove(path); err != nil {
			log.Printf("%s BLOB_FILE_ERROR OP: DELETEBLOB Key: %s Filename: %s Error: Failed to delete BLOB file: %v", logPrefix, req.Key, path, err)
			writeJSON(conn, Response{Status: "WARNING", Op: "DELETEBLOB", Key: req.Key, Message: fmt.Sprintf("BLOB object deleted, but file removal failed: %v", err)})
			delete(db.Store, req.Key)
			return
		}
		log.Printf("%s BLOB_FILE_DELETED OP: DELETEBLOB Key: %s Filename: %s", logPrefix, req.Key, path)
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

func handlePutBlobRequest(conn net.Conn, req Request, userID string, logPrefix string) {
	if req.Key == "" || req.ClientPath == "" || req.BlobSize <= 0 {
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: "Key, ClientPath, and BlobSize are required."})
		return
	}
	
	if perm := checkPermission(userID, req.Key); perm < PermWrite {
		writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Write access required."})
		log.Printf("%s OP_REJECTED OP: PUTBLOB Key: %s User: %s", logPrefix, req.Key, userID)
		return
	}

	baseName := filepath.Base(req.ClientPath)
	serverBlobPath := filepath.Join(blobStorageDir, req.Key+"_"+baseName)

	file, err := os.Create(serverBlobPath)
	if err != nil {
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: fmt.Sprintf("Failed to create file: %v", err)})
		return
	}
	defer file.Close()

	log.Printf("%s BLOB_TRANSFER_START OP: PUTBLOB Key: %s Size: %d bytes. User: %s", logPrefix, req.Key, req.BlobSize, userID)

	n, err := io.CopyN(file, conn, req.BlobSize)

	if err != nil {
		os.Remove(serverBlobPath)
		writeJSON(conn, Response{Status: "ERROR", Op: "PUTBLOB", Message: fmt.Sprintf("Transfer failed after %d bytes: %v", n, err)})
		return
	}

	if n != req.BlobSize {
		os.Remove(serverBlobPath)
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

	log.Printf("%s OP_SUCCESS OP: PUTBLOB Key: %s Filename: %s User: %s", logPrefix, req.Key, serverBlobPath, userID)
	writeJSON(conn, Response{
		Status: "OK",
		Op: "PUTBLOB",
		Message: fmt.Sprintf("BLOB stored successfully. Size: %d bytes.", req.BlobSize),
		BlobSize: req.BlobSize,
		BlobPath: serverBlobPath,
	})
}

func handleGetBlobRequest(conn net.Conn, req Request, userID string, logPrefix string) {
	if req.Key == "" {
		writeJSON(conn, Response{Status: "ERROR", Op: "GETBLOB", Message: "Key is required for GETBLOB."})
		return
	}
	
	if perm := checkPermission(userID, req.Key); perm < PermRead {
		writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Read access required."})
		log.Printf("%s OP_REJECTED OP: GETBLOB Key: %s User: %s", logPrefix, req.Key, userID)
		return
	}

	db.Lock.RLock()
	value, ok := db.Store[req.Key]
	db.Lock.RUnlock()

	if !ok {
		writeJSON(conn, Response{Status: "NOT_FOUND", Op: "GETBLOB", Key: req.Key, Message: "Key not found."})
		return
	}

	metadata, ok := value.(map[string]interface{})
	if !ok || metadata["type"] != "BLOB" {
		writeJSON(conn, Response{Status: "ERROR", Op: "GETBLOB", Message: "Key is not a BLOB object."})
		return
	}

	serverBlobPath, pathOK := metadata["path"].(string)
	blobSizeFloat, sizeOK := metadata["size"].(float64)
	blobSize := int64(blobSizeFloat)

	if !pathOK || !sizeOK || serverBlobPath == "" || blobSize <= 0 {
		writeJSON(conn, Response{Status: "ERROR", Op: "GETBLOB", Message: "BLOB metadata is corrupted."})
		return
	}

	writeJSON(conn, Response{
		Status: "OK",
		Op: "GETBLOB",
		Key: req.Key,
		Message: fmt.Sprintf("Starting BLOB transfer. Size: %d bytes.", blobSize),
		BlobSize: blobSize,
		BlobPath: serverBlobPath,
		Value: metadata,
	})

	file, err := os.Open(serverBlobPath)
	if err != nil {
		log.Printf("%s BLOB_FILE_ERROR OP: GETBLOB Key: %s Filename: %s Error: Failed to open file: %v", logPrefix, req.Key, serverBlobPath, err)
		return
	}
	defer file.Close()

	log.Printf("%s BLOB_TRANSFER_START OP: GETBLOB Key: %s streaming %d bytes. User: %s", logPrefix, req.Key, blobSize, userID)
	n, err := io.Copy(conn, file)

	if err != nil {
		log.Printf("%s BLOB_TRANSFER_ERROR OP: GETBLOB Key: %s Error: Stream failed after %d bytes: %v", logPrefix, req.Key, n, err)
	} else if n != blobSize {
		log.Printf("%s BLOB_TRANSFER_ERROR OP: GETBLOB Key: %s Error: Stream size mismatch, expected %d, transferred %d", logPrefix, req.Key, blobSize, n)
	} else {
		log.Printf("%s OP_SUCCESS OP: GETBLOB Key: %s Transfer complete. User: %s", logPrefix, req.Key, userID)
	}
}

// --- Persistence Commands (Server Side) ---

func handleDumpRequest(conn net.Conn, req Request, userID string, logPrefix string) {
	if perm := checkPermission(userID, "security_db"); perm < PermAdmin {
		writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Admin privileges required for DUMP."})
		log.Printf("%s OP_REJECTED OP: DUMP User: %s", logPrefix, userID)
		return
	}

	filename := req.Filename
	if filename == "" {
		filename = *dumpFilenamePtr
	}
	securityFilename := *securityDumpFilenamePtr

	if err := dumpToFile(filename, "CLIENT"); err != nil {
		writeJSON(conn, Response{Status: "ERROR", Op: "DUMP", Message: fmt.Sprintf("Failed to dump data: %v", err)})
		return
	}
	
	if err := dumpSecurityDB("CLIENT"); err != nil {
		writeJSON(conn, Response{Status: "ERROR", Op: "DUMP", Message: fmt.Sprintf("Data dumped, but FAILED to dump security DB: %v", err)})
		return
	}

	writeJSON(conn, Response{Status: "OK", Op: "DUMP", Message: fmt.Sprintf("Data dumped to %s, Security DB dumped to %s.", filename, securityFilename)})
	log.Printf("%s OP_SUCCESS OP: DUMP Data: %s, Security: %s User: %s", logPrefix, filename, securityFilename, userID)
}

func handleLoadRequest(conn net.Conn, req Request, userID string, logPrefix string) {
	if perm := checkPermission(userID, "security_db"); perm < PermAdmin {
		writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Admin privileges required for LOAD."})
		log.Printf("%s OP_REJECTED OP: LOAD User: %s", logPrefix, userID)
		return
	}

	if loadSecurityDB() {
		setupDefaultSecurity()
	} else {
		setupDefaultSecurity()
	}

	filename := req.Filename
	if filename == "" {
		writeJSON(conn, Response{Status: "ERROR", Op: "LOAD", Message: "Filename is required for LOAD."})
		return
	}

	loadStoreFromFile(filename)

	db.Lock.RLock()
	count := len(db.Store)
	db.Lock.RUnlock()

	writeJSON(conn, Response{
		Status: "OK",
		Op: "LOAD",
		Message: fmt.Sprintf("Load operation attempted on %s. Security DB reloaded/defaulted. Total store size: %d.", filename, count),
	})
	log.Printf("%s OP_SUCCESS OP: LOAD Filename: %s Total keys: %d User: %s", logPrefix, filename, count, userID)
}

// --- Core CRUD, Search, and Bulk Delete (Server Side) ---

func handleRequest(conn net.Conn, req Request, userID string, logPrefix string) {
	op := strings.ToUpper(req.Op)

	switch op {
	case "SET":
		if req.Key == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for SET."})
			return
		}
		if perm := checkPermission(userID, req.Key); perm < PermWrite {
			writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Write access required."})
			log.Printf("%s OP_REJECTED OP: SET Key: %s User: %s", logPrefix, req.Key, userID)
			return
		}

		db.Lock.Lock()
		db.Store[req.Key] = req.Value
		db.Lock.Unlock()
		writeJSON(conn, Response{Status: "OK", Op: "SET", Key: req.Key, Message: "Key set successfully."})
		log.Printf("%s OP_SUCCESS OP: SET Key: %s User: %s", logPrefix, req.Key, userID)

	case "GET":
		if req.Key == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for GET."})
			return
		}
		if perm := checkPermission(userID, req.Key); perm < PermRead {
			writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Read access required."})
			log.Printf("%s OP_REJECTED OP: GET Key: %s User: %s", logPrefix, req.Key, userID)
			return
		}

		db.Lock.RLock()
		value, ok := db.Store[req.Key]
		db.Lock.RUnlock()
		if !ok {
			writeJSON(conn, Response{Status: "NOT_FOUND", Op: "GET", Key: req.Key, Message: "Key not found."})
			return
		}
		writeJSON(conn, Response{Status: "OK", Op: "GET", Key: req.Key, Value: value})
		log.Printf("%s OP_SUCCESS OP: GET Key: %s User: %s", logPrefix, req.Key, userID)

	case "DELETE":
		if req.Key == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key is required for DELETE."})
			return
		}
		if perm := checkPermission(userID, req.Key); perm < PermDelete {
			writeJSON(conn, Response{Status: "AUTH_REJECTED", Message: "Permission denied. Delete access required."})
			log.Printf("%s OP_REJECTED OP: DELETE Key: %s User: %s", logPrefix, req.Key, userID)
			return
		}

		db.Lock.Lock()
		value, ok := db.Store[req.Key]
		if ok {
			if metadata, isBlob := value.(map[string]interface{}); isBlob && metadata["type"] == "BLOB" {
				if path, pOK := metadata["path"].(string); pOK {
					if err := os.Remove(path); err != nil {
						log.Printf("%s BLOB_FILE_ERROR OP: DELETE Key: %s Error: Failed to delete BLOB file: %v", logPrefix, req.Key, err)
					} else {
						log.Printf("%s BLOB_FILE_DELETED OP: DELETE Key: %s", logPrefix, req.Key)
					}
				}
			}
			delete(db.Store, req.Key)
		}
		db.Lock.Unlock()

		if !ok {
			writeJSON(conn, Response{Status: "NOT_FOUND", Op: "DELETE", Key: req.Key, Message: "Key not found."})
			return
		}
		writeJSON(conn, Response{Status: "OK", Op: "DELETE", Key: req.Key, Message: "Key and associated BLOB (if present) deleted successfully."})
		log.Printf("%s OP_SUCCESS OP: DELETE Key: %s User: %s", logPrefix, req.Key, userID)

	case "SEARCHKEY":
		if req.KeySubstring == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key substring is required for SEARCHKEY."})
			return
		}

		db.Lock.RLock()
		defer db.Lock.RUnlock()

		results := make(map[string]interface{})
		substring := strings.ToLower(req.KeySubstring)

		for key, value := range db.Store {
			if perm := checkPermission(userID, key); perm >= PermRead {
				if strings.Contains(strings.ToLower(key), substring) {
					results[key] = value
				}
			}
		}

		writeJSON(conn, Response{
			Status: "OK",
			Op: "SEARCHKEY",
			Message: fmt.Sprintf("Found %d authorized keys containing '%s'.", len(results), req.KeySubstring),
			SearchResults: results,
		})
		log.Printf("%s OP_SUCCESS OP: SEARCHKEY Substring: %s Found: %d User: %s", logPrefix, req.KeySubstring, len(results), userID)

	case "SEARCH":
		if req.SearchValue == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Search value is required for SEARCH."})
			return
		}

		db.Lock.RLock()
		defer db.Lock.RUnlock()

		results := make(map[string]interface{})
		searchTerm := strings.ToLower(req.SearchValue)

		for key, value := range db.Store {
			if perm := checkPermission(userID, key); perm >= PermRead {

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
		}

		writeJSON(conn, Response{
			Status: "OK",
			Op: "SEARCH",
			Message: fmt.Sprintf("Found %d authorized entries matching '%s'.", len(results), req.SearchValue),
			SearchResults: results,
		})
		log.Printf("%s OP_SUCCESS OP: SEARCH SearchValue: %s Found: %d User: %s", logPrefix, req.SearchValue, len(results), userID)

	case "DELETEKEY":
		if req.KeySubstring == "" {
			writeJSON(conn, Response{Status: "ERROR", Message: "Key substring is required for DELETEKEY."})
			return
		}

		db.Lock.Lock()
		defer db.Lock.Unlock()

		substring := strings.ToLower(req.KeySubstring)
		deletedCount := 0
		keysToDelete := []string{}

		for key := range db.Store {
			if perm := checkPermission(userID, key); perm >= PermDelete { 
				if strings.Contains(strings.ToLower(key), substring) {
					keysToDelete = append(keysToDelete, key)
				}
			}
		}

		for _, key := range keysToDelete {
			value := db.Store[key]
			if metadata, isBlob := value.(map[string]interface{}); isBlob && metadata["type"] == "BLOB" {
				if path, pOK := metadata["path"].(string); pOK {
					if err := os.Remove(path); err != nil {
						log.Printf("%s BLOB_FILE_ERROR OP: DELETEKEY Key: %s Error: Failed to delete BLOB file: %v", logPrefix, key, err)
					} else {
						log.Printf("%s BLOB_FILE_DELETED OP: DELETEKEY Key: %s", logPrefix, key)
					}
				}
			}
			delete(db.Store, key)
			deletedCount++
		}

		writeJSON(conn, Response{
			Status: "OK",
			Op: "DELETEKEY",
			Message: fmt.Sprintf("Successfully deleted %d keys containing '%s' for which you had Delete permission.", deletedCount, req.KeySubstring),
			DeletedCount: deletedCount,
		})
		log.Printf("%s OP_SUCCESS OP: DELETEKEY Substring: %s Deleted: %d User: %s", logPrefix, req.KeySubstring, deletedCount, userID)

	case "HELP":
		writeJSON(conn, Response{Status: "INFO", Op: "HELP", Message: "See shell output for commands."})

	default:
		writeJSON(conn, Response{Status: "ERROR", Message: "Unknown operation: " + req.Op})
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
		InsecureSkipVerify: true, // Typically needed in development/self-signed setups
	}
	return config, nil
}

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

    if tlsConn, ok := currentConn.(*tls.Conn); ok {
        if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
            clientCertCN = tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
        } else {
            clientCertCN = "NO_CERT"
        }
    } else {
        clientCertCN = "NO_TLS"
    }

	rawResponse, err := currentReader.ReadString('\n')
	if err != nil {
		log.Printf("CLIENT_WARNING: Failed to read initial server message: %v", err)
	} else {
		var resp Response
		if json.Unmarshal([]byte(rawResponse), &resp) == nil {
			fmt.Printf("Connection established to %s:%d (Client Cert: %s).\n", host, port, dynamicConfig.CertPath)
			fmt.Printf("Server INFO: %s\n", resp.Message)
		} else {
			fmt.Printf("Connection established to %s:%d (Client Cert: %s). Server sent raw response: %s\n", host, port, dynamicConfig.CertPath, rawResponse)
		}
	}

	log.Printf("CLIENT_CONNECT_SUCCESS: Connected to %s:%d, CN: %s", host, port, clientCertCN)
	return nil
}

func disconnectServer() {
	if currentConn == nil {
		fmt.Println("Warning: Already disconnected.")
		return
	}

	currentConn.Close()
	currentConn = nil
	currentReader = nil
	sessionToken = ""
	sessionUserID = ""
	clientCertCN = ""
	fmt.Printf("Disconnected from %s:%d. Session token and user ID cleared.\n", dynamicConfig.Host, dynamicConfig.Port)
	log.Printf("CLIENT_DISCONNECT_ACTION: Disconnected from %s:%d", dynamicConfig.Host, dynamicConfig.Port)
}

func runShell() {
	if err := connectToServer(); err != nil {
		fmt.Printf("Initial connection failed: %v. Please use 'CONNECT ...' to establish a connection.\n", err)
	}

	shellReader := bufio.NewReader(os.Stdin)
	for {
		connStatus := "DISCONNECTED"
		if currentConn != nil {
			connStatus = fmt.Sprintf("%s:%d", dynamicConfig.Host, dynamicConfig.Port)
		}

		clientIDPart := clientCertCN
		if clientIDPart == "" {
			clientIDPart = "N/A"
		}
        
		userIDPart := "NOLOGIN" 
		if sessionUserID != "" {
			userIDPart = sessionUserID
		}

        // CORRECTED: Displays [User ID @ Host:Port : Client CN]
        prompt := fmt.Sprintf("[%s@%s : %s]> ", userIDPart, connStatus, clientIDPart)

		fmt.Print(prompt)

		input, _ := shellReader.ReadString('\n')
		input = strings.TrimSpace(input)

		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}
		op := strings.ToUpper(parts[0])

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
		
		// --- RECTIFIED MYADDRESS COMMAND ---
		if op == "MYADDRESS" {
			if currentConn != nil {
				serverAddr := fmt.Sprintf("%s:%d", dynamicConfig.Host, dynamicConfig.Port)
				// Use currentConn.LocalAddr() to get the client's local side of the connection
				clientLocalAddr := currentConn.LocalAddr().String() 
				
				fmt.Printf("Connection Details:\n")
				fmt.Printf("  Server (Remote) Address: %s\n", serverAddr)
				fmt.Printf("  Client (Local) Address:  %s\n", clientLocalAddr)
			} else {
				fmt.Println("Not currently connected to a server.")
			}
			continue
		}
		// --- END RECTIFIED MYADDRESS COMMAND ---
		
		if op == "CLIENTID" {
			if currentConn != nil {
				fmt.Printf("mTLS Client ID (Common Name): %s\n", clientCertCN)
			} else {
				fmt.Println("Not currently connected. Client ID is based on mTLS connection.")
			}
			continue
		}
		// --- END NEW COMMANDS ---

		if op == "CONNECT" {
			sessionUserID = "" 
			clientCertCN = ""
			handleClientConnect(input)
			continue
		}

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
		
		if req.Op == "LOGIN" {
			rawResponse, err := sendRequestAndHandleBlob(req) 
			if err != nil {
				fmt.Println("Communication Error:", err)
				continue
			}
			var resp Response
			if json.Unmarshal([]byte(rawResponse), &resp) == nil && resp.Status == "OK" {
				sessionToken = resp.Token
				sessionUserID = req.UserID
				fmt.Printf("Login Successful. Token stored: %s... (use LOGOUT to end session)\n", sessionToken[:10])
			}
			fmt.Println(rawResponse)
			continue
		}

		if req.Op == "LOGOUT" {
			if sessionToken == "" {
				fmt.Println("Already logged out.")
				continue
			}
			req.Token = sessionToken
			rawResponse, err := sendRequestAndHandleBlob(req)
			if err == nil {
				sessionToken = ""
				sessionUserID = ""
			}
			fmt.Println(rawResponse)
			continue
		}

		if sessionToken == "" && op != "HELP" && op != "CONNECT" && op != "DISCONNECT" && op != "MYADDRESS" && op != "CLIENTID" {
			fmt.Println("Error: Not authenticated. Use 'LOGIN <user> <password>' first to get a token.")
			continue
		}
		req.Token = sessionToken
		
		rawResponse, err := sendRequestAndHandleBlob(req)

		if err != nil {
			if strings.Contains(err.Error(), "connection lost") {
				fmt.Println("Connection lost. Server disconnected unexpectedly.")
				currentConn = nil
				currentReader = nil
				sessionToken = ""
				sessionUserID = ""
				continue
			}
			fmt.Println("Communication Error:", err)
			continue
		}

		fmt.Println(rawResponse)
	}
}

func handleClientConnect(input string) {
	log.Printf("CLIENT_ACTION: CONNECT command received: %s", input)
	parts := strings.Fields(input)
	newConfig := dynamicConfig
	tempHost := ""
	tempPort := 0
	
	for i := 1; i < len(parts); i++ {
		arg := strings.ToLower(parts[i])
		if arg == "-h" || arg == "--host" {
			if i+1 < len(parts) {
				tempHost = parts[i+1]
				i++
			} else {
				fmt.Println("Error: Missing host value after -h/--host.")
				return
			}
		} else if arg == "-p" || arg == "--port" {
			if i+1 < len(parts) {
				p, err := strconv.Atoi(parts[i+1])
				if err != nil {
					fmt.Println("Error: Invalid port number after -p/--port. Port must be numeric.")
					return
				}
				tempPort = p
				i++
			} else {
				fmt.Println("Error: Missing port value after -p/--port.")
				return
			}
		} else if arg == "-ca" || arg == "--ca-cert" {
			if i+1 < len(parts) {
				newConfig.CACertPath = parts[i+1]
				i++
			} else {
				fmt.Println("Error: Missing CA certificate path after -ca/--ca-cert.")
				return
			}
		} else if arg == "-c" || arg == "--cert" {
			if i+1 < len(parts) {
				newConfig.CertPath = parts[i+1]
				i++
			} else {
				fmt.Println("Error: Missing client certificate path after -c/--cert.")
				return
			}
		} else if arg == "-k" || arg == "--key" {
			if i+1 < len(parts) {
				newConfig.KeyPath = parts[i+1]
				i++
			} else {
				fmt.Println("Error: Missing client key path after -k/--key.")
				return
			}
		} else {
			fmt.Printf("Error: Unknown argument or missing flag value '%s'.\n", parts[i])
			return
		}
	}

	if tempHost != "" {
		newConfig.Host = tempHost
	}
	if tempPort != 0 {
		newConfig.Port = tempPort
	}

	if newConfig.Host == "" || newConfig.Port == 0 {
		fmt.Println("Error: Host (-h/--host) and Port (-p/--port) must be specified.")
		return
	}

	dynamicConfig = newConfig
	if err := connectToServer(); err != nil {
		fmt.Println("Connection attempt failed:", err)
	}
}

func sendRequestAndHandleBlob(req Request) (string, error) {
	if currentConn == nil || currentReader == nil {
		return "", fmt.Errorf("connection lost or not established")
	}

	reqJSON, _ := json.Marshal(req)

	if _, err := currentConn.Write(append(reqJSON, '\n')); err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "closed network connection") {
			return "", fmt.Errorf("connection lost: Server disconnected")
		}
		return "", fmt.Errorf("failed to send request JSON: %w", err)
	}

	if strings.ToUpper(req.Op) == "PUTBLOB" {
		file, err := os.Open(req.ClientPath)
		if err != nil {
			return "", fmt.Errorf("failed to open client file for BLOB: %w", err)
		}
		defer file.Close()

		log.Printf("CLIENT_BLOB_UPLOAD_START: Key: %s, Size: %d bytes.", req.Key, req.BlobSize)
		if n, err := io.Copy(currentConn, file); err != nil || n != req.BlobSize {
			if err != nil && err != io.EOF {
				return "", fmt.Errorf("error during BLOB stream: %w", err)
			}
			return "", fmt.Errorf("BLOB stream size mismatch: expected %d, sent %d", req.BlobSize, n)
		}
		log.Printf("CLIENT_BLOB_UPLOAD_COMPLETE: Key: %s", req.Key)
	}

	rawResponse, err := currentReader.ReadString('\n')
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "closed network connection") {
			return "", fmt.Errorf("connection lost: Server disconnected while reading response")
		}
		return "", fmt.Errorf("error reading server response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal([]byte(rawResponse), &resp); err != nil {
		return rawResponse, fmt.Errorf("error parsing server JSON response: %w (Raw: %s)", err, rawResponse)
	}

	if strings.ToUpper(req.Op) == "GETBLOB" && resp.Status == "OK" && resp.BlobSize > 0 {
		return handleBlobRetrieval(resp)
	}

	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	return string(respJSON), nil
}

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
	localPath := "retrieved_" + resp.Key + "_" + originalName

	file, err := os.Create(localPath)
	if err != nil {
		log.Printf("CLIENT_BLOB_DOWNLOAD_ERROR: Key: %s, Failed to create local file %s: %v", resp.Key, localPath, err)
		return "", fmt.Errorf("failed to create local file %s: %w", localPath, err)
	}
	defer file.Close()

	log.Printf("CLIENT_BLOB_DOWNLOAD_START: Key: %s, Size: %d bytes, saving to %s...", resp.Key, resp.BlobSize, localPath)

	n, err := io.CopyN(file, currentReader, resp.BlobSize)

	if err != nil && err != io.EOF {
		os.Remove(localPath)
		return "", fmt.Errorf("error during BLOB retrieval: %w", err)
	}

	if n != resp.BlobSize {
		os.Remove(localPath)
		return "", fmt.Errorf("BLOB size mismatch: expected %d, received %d", resp.BlobSize, n)
	}

	log.Printf("CLIENT_BLOB_DOWNLOAD_COMPLETE: Key: %s, Saved to %s", localPath)
	resp.Message = fmt.Sprintf("BLOB retrieved successfully. Saved to: %s", localPath)
	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	return string(respJSON), nil
}

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
		if err != nil || fileInfo.IsDir() || fileInfo.Size() == 0 {
			return Request{}, fmt.Errorf("invalid BLOB file path or empty file")
		}
		req.BlobSize = fileInfo.Size()
		
	case "LOGIN":
		if len(parts) != 3 {
			return Request{}, fmt.Errorf("LOGIN requires user ID and password. Usage: LOGIN <user_id> <password>")
		}
		req.UserID = parts[1]
		req.Password = parts[2]
		
	case "LOGOUT":
		if len(parts) > 1 {
			return Request{}, fmt.Errorf("LOGOUT takes no arguments. Usage: LOGOUT")
		}

    case "CHANGEPASSWORD":
        if len(parts) != 3 {
            return Request{}, fmt.Errorf("CHANGEPASSWORD requires ID and new password. Usage: CHANGEPASSWORD <id> <new_password>")
        }
        req.UserID = parts[1]
        req.Password = parts[2]
        
    case "UPDATEUSER":
        if len(parts) < 4 || strings.ToLower(parts[2]) != "-groups" {
            return Request{}, fmt.Errorf("UPDATEUSER requires ID and -groups flag. Usage: UPDATEUSER <id> -groups <group1,group2,...>")
        }
        req.UserID = parts[1]
        req.Groups = strings.Split(parts[3], ",")

    case "CREATEUSER":
        if len(parts) != 3 {
            return Request{}, fmt.Errorf("CREATEUSER requires ID and password. Usage: CREATEUSER <id> <password>")
        }
        req.UserID = parts[1]
        req.Password = parts[2]
		
	case "DELETEUSER", "VIEWUSER":
		if len(parts) < 1 || len(parts) > 2 {
			return Request{}, fmt.Errorf("%s takes 0 or 1 argument. Usage: %s [id]", op, op)
		}
		if len(parts) == 2 {
			req.UserID = parts[1]
		}
		
    case "UPDATEGROUP":
        if len(parts) < 4 || strings.ToLower(parts[2]) != "-members" {
            return Request{}, fmt.Errorf("UPDATEGROUP requires name and -members flag. Usage: UPDATEGROUP <name> -members <user1,user2,...>")
        }
        req.GroupName = parts[1]
        req.Members = strings.Split(parts[3], ",")
        
    case "ADDUSERTOGROUP", "REMOVEUSERFROMGROUP":
        if len(parts) != 3 {
            return Request{}, fmt.Errorf("%s requires User ID and Group Name. Usage: %s <user_id> <group_name>", op, op)
        }
        req.UserID = parts[1]
        req.GroupName = parts[2]

	case "CREATEGROUP":
		if len(parts) != 2 {
			return Request{}, fmt.Errorf("CREATEGROUP requires a name. Usage: CREATEGROUP <name>")
		}
		req.GroupName = parts[1]
		
	case "DELETEGROUP", "VIEWGROUP":
		if len(parts) < 1 || len(parts) > 2 {
			return Request{}, fmt.Errorf("%s takes 0 or 1 argument. Usage: %s [name]", op, op)
		}
		if len(parts) == 2 {
			req.GroupName = parts[1]
		}
        
	case "SETACL", "SETPERM":
		if len(parts) != 5 {
			return Request{}, fmt.Errorf("%s usage: %s <key> <user/group> <id> <permission 0-4>", op, op)
		}
		req.Key = parts[1]
		targetType := strings.ToLower(parts[2])
		targetID := parts[3]
		perm, err := strconv.Atoi(parts[4])
		if err != nil || perm < 0 || perm > 4 {
			return Request{}, fmt.Errorf("invalid permission level. Must be 0 (NONE) to 4 (ADMIN)")
		}
		req.Permission = perm
		if targetType == "user" {
			req.ACLUserID = targetID
		} else if targetType == "group" {
			req.ACLGroupName = targetID
		} else {
			return Request{}, fmt.Errorf("invalid ACL target type: must be 'user' or 'group'")
		}

	case "REMOVEPERM":
		if len(parts) != 4 {
			return Request{}, fmt.Errorf("REMOVEPERM usage: REMOVEPERM <key> <user/group> <id>")
		}
		req.Key = parts[1]
		targetType := strings.ToLower(parts[2])
		targetID := parts[3]
		if targetType == "user" {
			req.ACLUserID = targetID
		} else if targetType == "group" {
			req.ACLGroupName = targetID
		} else {
			return Request{}, fmt.Errorf("invalid ACL target type: must be 'user' or 'group'")
		}
        
    case "UPDATEACL":
        if len(parts) != 3 {
            return Request{}, fmt.Errorf("UPDATEACL requires key and default perm. Usage: UPDATEACL <key> <default_perm 0-4>")
        }
        req.Key = parts[1]
        perm, err := strconv.Atoi(parts[2])
		if err != nil || perm < 0 || perm > 4 {
			return Request{}, fmt.Errorf("invalid permission level. Must be 0 (NONE) to 4 (ADMIN)")
		}
        req.Permission = perm

	case "VIEWACL", "DELETEACL":
		if len(parts) < 1 || len(parts) > 2 {
			return Request{}, fmt.Errorf("%s takes 0 or 1 argument. Usage: %s [key]", op, op)
		}
		if len(parts) == 2 {
			req.Key = parts[1]
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

	case "HELP", "CONNECT", "DISCONNECT", "MYADDRESS", "CLIENTID":
	default:
		return Request{}, fmt.Errorf("unknown operation: %s", op)
	}
	return req, nil
}

func printHelp() {
	fmt.Println("\n--- 🔐 Authentication & Authorization (REQUIRED) ---")
	fmt.Println("LOGIN <user_id> <password>     - Establish a session and get a token (Password Hashed on Server).")
	fmt.Println("LOGOUT                         - Terminate the current session.")
	
	fmt.Println("\n--- 👤 User & Group Management (Admin Required, Persisted) ---")
	fmt.Println("CREATEUSER <id> <password>     - Create a new user (password is HASHED).")
	fmt.Println("CHANGEPASSWORD <id> <password> - Change a user's password.")
	fmt.Println("UPDATEUSER <id> -groups <list> - Replace user's group list (comma separated, one-way update).")
	fmt.Println("ADDUSERTOGROUP <user> <group>  - Add a user to a specific group (two-way update).")
	fmt.Println("REMOVEUSERFROMGROUP <user> <group> - Remove a user from a specific group (two-way update).")
	fmt.Println("VIEWUSER [id]                  - View all user IDs, or details for one.")
	fmt.Println("DELETEUSER <id>                - Delete user, clean up groups/ACLs/sessions.")
	fmt.Println("CREATEGROUP <name>             - Create a new group.")
	fmt.Println("UPDATEGROUP <name> -members <list> - Replace group's member list (comma separated, two-way update).")
	fmt.Println("VIEWGROUP [name]               - View all group names, or members of one.")
	fmt.Println("DELETEGROUP <name>             - Delete group, clean up user memberships/ACLs.")

	fmt.Println("\n--- 🔒 Access Control List (ACL) Management (Admin Required, Persisted) ---")
	fmt.Println("UPDATEACL <key> <perm 0-4>     - Set the **default** permission for a key's ACL.")
	fmt.Println("SETPERM <key> <u/g> <id> <p>   - Set/Update explicit permission (0-4) for user/group on key.")
	fmt.Println("REMOVEPERM <key> <u/g> <id>    - Remove explicit permission for user/group on key.")
	fmt.Println("VIEWACL [key]                  - View all keys with ACLs, or details for one.")
	fmt.Println("DELETEACL <key>                - Remove the entire explicit ACL for a data key.")
	fmt.Println("    Permissions:")
	fmt.Println("        0=NONE, 1=READ, 2=WRITE, 3=DELETE, 4=ADMIN")
	
	fmt.Println("\n--- 📦 Key-Value Data Store Commands (Requires Token) ---")
	fmt.Println("SET <key> <value/json>         - Set a key-value pair (Requires WRITE/ADMIN perm).")
	fmt.Println("GET <key>                      - Retrieve value (Requires READ/ADMIN perm).")
	fmt.Println("DELETE <key>                   - Remove key/value/BLOB (Requires DELETE/ADMIN perm).")

	fmt.Println("\n--- 🖼️ Binary Large Object (BLOB) Storage (Requires Token) ---")
	fmt.Println("PUTBLOB <key> <file>           - Store file as BLOB (Requires WRITE/ADMIN perm).")
	fmt.Println("GETBLOB <key>                  - Retrieve and save BLOB (Requires READ/ADMIN perm).")
	fmt.Println("DELETEBLOB <key>               - Explicitly remove BLOB (Requires DELETE/ADMIN perm).")

	fmt.Println("\n--- 🔎 Search & Bulk Delete (Requires Token) ---")
	fmt.Println("SEARCH <string>                - Find authorized keys and values.")
	fmt.Println("SEARCHKEY <substring>          - Find authorized keys by substring.")
	fmt.Println("DELETEKEY <substring>          - DANGER: Delete authorized keys by substring (Requires DELETE/ADMIN perm on each key).")

	fmt.Println("\n--- ⚙️ System & Connection (Local Shell Commands) ---")
	fmt.Printf("CONNECT -h <host> -p <port> -ca <path> -c <path> -k <path> - Connect/reconnect (mTLS).\n")
	fmt.Printf("DISCONNECT                     - Close the current connection and clear token.\n")
	fmt.Printf("MYADDRESS                      - Show the Server (Remote) and Client (Local) connection addresses.\n") // Updated help text
	fmt.Printf("CLIENTID                       - Show the mTLS Client ID (Common Name) used for the current connection.\n")
	fmt.Printf("DUMP [filename]                - Admin: Trigger dump of data (default: %s) and security (default: %s).\n", *dumpFilenamePtr, defaultSecurityDumpFilename)
	fmt.Printf("LOAD <filename>                - Admin: Trigger load of data (merges) and security (overwrites) from files.\n")
	fmt.Println("HELP                           - Show this help message.")
	fmt.Println("EXIT / QUIT                    - Close the shell.")
	fmt.Println("--------------------------\n")
}