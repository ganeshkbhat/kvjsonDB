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
	"strconv"
	"strings"
	"sync"
	"syscall"
	// "time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// --- Command-Line Flags (global variables for configuration) ---
var (
	modePtr *string
	loadPtr *string 
	
	hostPtr         *string
	serverCertPtr   *string
	serverKeyPtr    *string
	clientCertPtr   *string
	clientKeyPtr    *string
	caCertPtr       *string
	dumpFilenamePtr *string
)

// --- User and Role Management Structures ---

type User struct {
	Username    string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	UserEmail   string `json:"userEmail"`
	Deleted     bool   `json:"deleted"` 
	Role        string `json:"role"`    
}

type KeyACL struct {
    Roles map[string]Permissions `json:"roles"` 
}

type Permissions struct {
    Read bool `json:"read"`
    Write bool `json:"write"`
    Delete bool `json:"delete"`
}

// --- Global State ---
var (
	clientIdCounter int
	activeClients   = make(map[interface{}]*ClientConnection)
	clientsMutex    sync.Mutex
	store           = KeyValueStore{Data: make(map[string]interface{})}
	serverStopCh    = make(chan struct{}) 

	// Authentication/Authorization State
	users = make(map[string]User)          
	sessions = make(map[string]*ClientConnection) // session_token -> ClientConnection
	authMutex sync.RWMutex
    
    // ACL State
    keyACLs = make(map[string]KeyACL)      
    keyACLLock sync.RWMutex

    // Group State
    userGroups = make(map[string][]string) 
    groupLock sync.RWMutex

    availableRoles = []string{"admin", "user", "guest"}
)

// --- CRITICAL CHANGE 1: Enhanced ClientConnection for Session Binding ---
type ClientConnection struct {
	Socket net.Conn
	ID     interface{}
    SessionToken string 
    CurrentUser *User 
    // Stores the network address (IP:Port) for session binding
    RemoteAddress string 
}

// --- Shared Structures ---
type KeyValueStore struct {
	Data map[string]interface{}
	Lock sync.RWMutex
}

type Request struct {
	Op       string                 `json:"op"`
	Key      string                 `json:"key,omitempty"`
	Value    interface{}            `json:"value,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	Filename string                 `json:"filename,omitempty"`
	Term     interface{}            `json:"term,omitempty"`
	Message  string                 `json:"message,omitempty"`
	NewID    interface{}            `json:"newId,omitempty"`
    Username string                 `json:"username,omitempty"`
    Password string                 `json:"password,omitempty"`
    NewPassword string              `json:"newPassword,omitempty"`
    UserEmail string                `json:"userEmail,omitempty"`
    Role string                     `json:"role,omitempty"`
    
    ACLRole string                  `json:"aclRole,omitempty"`   
    ACLPerm string                  `json:"aclPerm,omitempty"`   
    GroupName string                `json:"groupName,omitempty"` 
}

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
    Token    string      `json:"token,omitempty"`
}

// --- Authorization and Utility Functions ---

func hasPermission(client *ClientConnection, requiredRole string) bool {
    if client.CurrentUser == nil || client.CurrentUser.Deleted {
        return false
    }

    userRole := client.CurrentUser.Role

    if requiredRole == "admin" {
        return userRole == "admin"
    }
    if requiredRole == "user" {
        return userRole == "admin" || userRole == "user"
    }
    if requiredRole == "guest" {
        return userRole == "admin" || userRole == "user" || userRole == "guest"
    }
    return false 
}

func isUserInGroup(username string, groupName string) bool {
    groupLock.RLock()
    defer groupLock.RUnlock()
    
    if users, exists := userGroups[groupName]; exists {
        for _, u := range users {
            if u == username {
                return true
            }
        }
    }
    return false
}

func checkPermissionForKey(client *ClientConnection, key string, requiredPerm string) bool {
    if !isAuthenticated(client) {
        return false
    }

    // Global Access Group Check
    if isUserInGroup(client.CurrentUser.Username, "global_db_access") {
        return true
    }

    // ACL Check
    keyACLLock.RLock()
    defer keyACLLock.RUnlock()

    acl, exists := keyACLs[key]
    if !exists {
        return false 
    }

    perms, roleHasACL := acl.Roles[client.CurrentUser.Role]
    if !roleHasACL {
        return false
    }

    switch requiredPerm {
    case "R":
        return perms.Read
    case "W":
        return perms.Write
    case "D":
        return perms.Delete
    default:
        return false
    }
}

// --- Authentication Functions ---

func hashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

func authenticateUser(username string, password string) *User {
	authMutex.RLock()
	user, exists := users[username]
	authMutex.RUnlock()

	if !exists || user.Deleted {
		return nil
	}

    err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
    if err == nil {
        return &user
    }
    return nil
}

func registerUser(username string, password string, email string, role string) error {
    if username == "" || password == "" || email == "" || role == "" {
        return fmt.Errorf("username, password, email, and role cannot be empty")
    }

    hashedPassword, err := hashPassword(password)
    if err != nil {
        return fmt.Errorf("failed to hash password: %w", err)
    }

	authMutex.Lock()
	defer authMutex.Unlock()
    
    if _, exists := users[username]; exists {
        return fmt.Errorf("user '%s' already exists", username)
    }
    
    newUser := User{
        Username: username,
        PasswordHash: hashedPassword,
        UserEmail: email,
        Deleted: false,
        Role: strings.ToLower(role),
    }

	users[username] = newUser
	log.Printf("🔒 Registered new user: %s (Role: %s)", username, newUser.Role)
	return nil
}

func generateSessionToken() string {
	return uuid.New().String()
}

// --- CRITICAL CHANGE 2: Session Binding Enforcement ---
func isAuthenticated(client *ClientConnection) bool {
	if client.SessionToken == "" || client.CurrentUser == nil || client.CurrentUser.Deleted {
		return false
	}
    
	authMutex.RLock()
	sessionClient, ok := sessions[client.SessionToken]
	authMutex.RUnlock()
    
    // Check 1: Does the token exist and point to a valid connection object?
    if !ok || sessionClient.CurrentUser == nil || sessionClient.CurrentUser.Deleted {
        return false 
    }
    
    // Check 2: Does the connection object belong to the client currently using it?
    if sessionClient != client {
        log.Printf("⚠️ WARNING: Token %s points to wrong connection object. Denying access.", client.SessionToken)
        return false
    }
    
    // CRITICAL: Check 3: Session Binding Check (IP:Port Verification)
    // If the current connection's address doesn't match the one recorded at login, deny and invalidate.
    if client.RemoteAddress != sessionClient.RemoteAddress {
        
        log.Printf("⚠️ SESSION HIJACK DETECTED: Token %s accessed from new address %s. Original: %s. Session invalidated.", 
            client.SessionToken, client.RemoteAddress, sessionClient.RemoteAddress)
        
        // Invalidate the session immediately upon detection of address mismatch
        authMutex.Lock()
        delete(sessions, client.SessionToken)
        authMutex.Unlock()
        
        // Use a diagram to illustrate the process
        // 
        
        return false 
    }

    return true
}

// --- Persistence Functions ---

func dumpStoreToFile(filename string) {
	log.Printf("⏳ Attempting graceful dump to %s...", filename)

	store.Lock.RLock()
	fileData, err := json.MarshalIndent(store.Data, "", "  ")
	store.Lock.RUnlock()

	if err != nil {
		log.Printf("❌ Failed to marshal data for dump: %v", err)
		return
	}

	err = os.WriteFile(filename, fileData, 0644)
	if err != nil {
		log.Printf("❌ Failed to write dump file: %v", err)
	} else {
		log.Printf("✅ Data successfully dumped to %s.", filename)
	}
}

func loadStoreFromFile(filename string) {
	log.Printf("⏳ Attempting to load data from %s...", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("⚠️ File %s not found. Starting with empty database.", filename)
			return
		}
		log.Printf("❌ Failed to read file %s: %v", filename, err)
		return
	}

	var loadedData map[string]interface{}
	if err := json.Unmarshal(data, &loadedData); err != nil {
		log.Printf("❌ Failed to unmarshal JSON from %s: %v. Starting with empty database.", filename, err)
		return
	}

	store.Lock.Lock()
	store.Data = loadedData
	store.Lock.Unlock()
	log.Printf("✅ Successfully loaded %d records from %s.", len(loadedData), filename)
}

// --- Flag Initialization ---

func init() {
	modePtr = flag.String("s", "", "Mode to run: 'db' or 'shell'")
	loadPtr = flag.String("l", "", "Load data from the specified JSON file on server startup (overrides -df for initial load)")
	
	hostPtr         = flag.String("h", "127.0.0.1", "Host interface to bind to (server) or connect to (shell)")
	serverCertPtr   = flag.String("sc", "server.crt", "Server certificate file path")
	serverKeyPtr    = flag.String("sk", "server.key", "Server private key file path")
	clientCertPtr   = flag.String("cc", "client.crt", "Client certificate file path")
	clientKeyPtr    = flag.String("ck", "client.key", "Client private key file path")
	caCertPtr       = flag.String("ca", "ca.crt", "Certificate authority file path")
	dumpFilenamePtr = flag.String("df", "store_dump.json", "Default file name for persistence (dump/auto-load)")
}

// --- Main Entry Point ---

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -s <db|shell> [-h <host>] [-l <file>] [-sc <file>] [-sk <file>] ... [port]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse() 

	port := "9999" 
	if len(flag.Args()) > 0 {
		port = flag.Args()[0]
	}

	switch *modePtr {
	case "db":
        authMutex.RLock()
        _, adminExists := users["admin"]
        authMutex.RUnlock()
        
        if !adminExists {
            if err := registerUser("admin", "password123", "admin@example.com", "admin"); err != nil && !strings.Contains(err.Error(), "user already exists") {
                log.Fatalf("Failed to register default user: %v", err)
            }
            groupLock.Lock()
            userGroups["global_db_access"] = []string{"admin"}
            groupLock.Unlock()
        }
        
		runServer(port, *loadPtr) 
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

func runServer(port string, loadFilename string) {
    
    fileToLoad := loadFilename
	if fileToLoad == "" {
		fileToLoad = *dumpFilenamePtr 
	}
	loadStoreFromFile(fileToLoad)
	
	defer dumpStoreToFile(*dumpFilenamePtr) 

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("⚠️ Received signal %v. Initiating graceful shutdown...", sig)
		
		close(serverStopCh) 
		os.Exit(0) 
	}()

	caCert, err := os.ReadFile(*caCertPtr)
	if err != nil {
		log.Fatalf("Error reading CA cert (%s): %v", *caCertPtr, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*serverCertPtr, *serverKeyPtr)
	if err != nil {
		log.Fatalf("Error loading server keypair: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, 
	}

	listener, err := tls.Listen("tcp", *hostPtr+":"+port, config)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("✅ Secure Key-Value DB Server running on %s:%s", *hostPtr, port)

	for {
		conn, err := listener.Accept()
		
		select {
		case <-serverStopCh:
			listener.Close()
			return 
		default:
		}
		
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			log.Println("Accept error:", err)
			continue
		}
		go handleServerConnection(conn)
	}
}

func handleServerConnection(conn net.Conn) {
	clientsMutex.Lock()
	clientIdCounter++
    
    // CRITICAL CHANGE 3: Initialize ClientConnection with RemoteAddress
	client := &ClientConnection{
        Socket: conn, 
        ID: clientIdCounter, 
        SessionToken: "", 
        CurrentUser: nil,
        RemoteAddress: conn.RemoteAddr().String(), // Store source IP:Port
    }
	activeClients[client.ID] = client
	clientsMutex.Unlock()

	defer func() {
		clientsMutex.Lock()
		delete(activeClients, client.ID)
		clientsMutex.Unlock()
        
        if client.SessionToken != "" {
            authMutex.Lock()
            delete(sessions, client.SessionToken)
            authMutex.Unlock()
            log.Printf("Session %s invalidated on disconnect for Client ID: %v", client.SessionToken, client.ID)
        }
        
		conn.Close()
		log.Printf("Connection closed for Client ID: %v (Address: %s)", client.ID, client.RemoteAddress)
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS Handshake failed for client %v: %s", client.ID, err)
			return
		}
	}

	log.Printf("🔗 New connection. Client ID: %v (Address: %s)", client.ID, client.RemoteAddress)

    writeJSON(conn, Response{Status: "INFO", Message: "Connection established. Please use LOGIN <username> <password>."})
    
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		rawMessage := scanner.Bytes()
		var req Request
		if err := json.Unmarshal(rawMessage, &req); err != nil {
			writeJSON(conn, Response{Status: "ERROR", Message: "Invalid JSON"})
			continue
		}

		switch req.Op {
        case "SHUTDOWN":
			handleShutdown(client, req)
			return 
		case "RESTART":
			handleRestart(client, req)
			return
        case "LOGIN":
            handleLogin(client, req)
        case "LOGOUT":
            handleLogout(client, req)
        case "CHANGE_PASSWORD":
            handleChangePassword(client, req)
            
        case "ADD_USER":
            handleAddUser(client, req)
        case "REMOVE_USER":
            handleRemoveUser(client, req)
            
        case "VIEW_USERS":
            handleViewUsers(client, req)
        case "VIEW_GROUPS":
            handleViewGroups(client, req)
        case "VIEW_ROLES":
            handleViewRoles(client, req)
        case "VIEW_ACL":
            handleViewACL(client, req)
            
        case "SET_ACL":
            handleSetACL(client, req)
        case "SET_GROUP":
            handleSetGroup(client, req)
            
		default:
			handleRequest(client, req)
		}
	}
}

// --- Handler Functions ---

func handleLogin(client *ClientConnection, req Request) {
    if req.Username == "" || req.Password == "" {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "LOGIN requires a username and password."})
        return
    }
    if isAuthenticated(client) {
        writeJSON(client.Socket, Response{Status: "INFO", Message: "Already logged in."})
        return
    }
    user := authenticateUser(req.Username, req.Password)
    if user != nil {
        token := generateSessionToken()
        authMutex.Lock()
        
        // Invalidate any old session this user might have (enforcing single session per user)
        for t, c := range sessions {
            if c.CurrentUser != nil && c.CurrentUser.Username == user.Username {
                delete(sessions, t)
                log.Printf("🔑 Old session %s for user %s invalidated by new login.", t, user.Username)
                break
            }
        }
        
        client.SessionToken = token
        client.CurrentUser = user 
        sessions[token] = client
        authMutex.Unlock()
        log.Printf("🔑 Client ID %v logged in as %s (Role: %s) from %s.", client.ID, user.Username, user.Role, client.RemoteAddress)
        writeJSON(client.Socket, Response{
            Status: "OK", 
            Op: "LOGIN", 
            Message: fmt.Sprintf("Authentication successful for user %s (Role: %s).", user.Username, user.Role),
            Token: token,
        })
    } else {
        log.Printf("❌ Client ID %v failed login for user %s", client.ID, req.Username)
        writeJSON(client.Socket, Response{Status: "UNAUTHORIZED", Op: "LOGIN", Message: "Invalid username or password."})
    }
}

func handleChangePassword(client *ClientConnection, req Request) {
    if !isAuthenticated(client) {
        writeJSON(client.Socket, Response{Status: "UNAUTHORIZED", Message: "Please LOGIN first."})
        return
    }
    if req.Password == "" || req.NewPassword == "" {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "CHANGE_PASSWORD requires current password and new password."})
        return
    }
    
    username := client.CurrentUser.Username
    authMutex.Lock()
    defer authMutex.Unlock()
    
    user := users[username]

    // Use bcrypt.CompareHashAndPassword for secure verification
    if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
        writeJSON(client.Socket, Response{Status: "UNAUTHORIZED", Message: "Current password incorrect."})
        return
    }
    
    newHash, err := hashPassword(req.NewPassword)
    if err != nil {
        log.Printf("Error hashing new password for %s: %v", username, err)
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "Failed to process new password."})
        return
    }
    
    user.PasswordHash = newHash
    users[username] = user 
    log.Printf("🔑 User %s successfully changed password.", username)
    writeJSON(client.Socket, Response{Status: "OK", Op: "CHANGE_PASSWORD", Message: "Password successfully changed."})
}

func handleLogout(client *ClientConnection, req Request) {
    if !isAuthenticated(client) {
        writeJSON(client.Socket, Response{Status: "INFO", Message: "Not currently logged in."})
        return
    }
    authMutex.Lock()
    if client.SessionToken != "" {
        delete(sessions, client.SessionToken)
    }
    client.SessionToken = ""
    client.CurrentUser = nil 
    authMutex.Unlock()
    log.Printf("🚪 Client ID %v logged out.", client.ID)
    writeJSON(client.Socket, Response{Status: "OK", Op: "LOGOUT", Message: "Successfully logged out."})
}
func handleAddUser(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "Only administrators can add new users."})
        return
    }
    if req.Username == "" || req.Password == "" || req.UserEmail == "" || req.Role == "" {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "ADD_USER requires username, password, userEmail, and role."})
        return
    }
    err := registerUser(req.Username, req.Password, req.UserEmail, req.Role)
    if err != nil {
        writeJSON(client.Socket, Response{Status: "ERROR", Op: "ADD_USER", Message: fmt.Sprintf("Failed to add user: %v", err)})
        return
    }
    writeJSON(client.Socket, Response{Status: "OK", Op: "ADD_USER", Message: fmt.Sprintf("User '%s' added successfully with role '%s'.", req.Username, req.Role)})
}
func handleRemoveUser(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "Only administrators can remove users."})
        return
    }
    if req.Username == "" {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "REMOVE_USER requires a username."})
        return
    }
    authMutex.Lock()
    defer authMutex.Unlock()
    user, exists := users[req.Username]
    if !exists {
        writeJSON(client.Socket, Response{Status: "NOT_FOUND", Message: fmt.Sprintf("User '%s' not found.", req.Username)})
        return
    }
    user.Deleted = true
    users[req.Username] = user
    for token, c := range sessions {
        if c.CurrentUser != nil && c.CurrentUser.Username == req.Username {
            delete(sessions, token)
            c.SessionToken = ""
            c.CurrentUser = nil
        }
    }
    log.Printf("❌ User '%s' soft-deleted.", req.Username)
    writeJSON(client.Socket, Response{Status: "OK", Op: "REMOVE_USER", Message: fmt.Sprintf("User '%s' successfully soft-deleted.", req.Username)})
}
func parsePermissions(permStr string) Permissions {
    perms := Permissions{}
    perms.Read = strings.Contains(permStr, "R")
    perms.Write = strings.Contains(permStr, "W")
    perms.Delete = strings.Contains(permStr, "D")
    return perms
}
func handleSetACL(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "SET_ACL requires admin privileges."})
        return
    }
    if req.Key == "" || req.ACLRole == "" || req.ACLPerm == "" {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "SET_ACL requires key, role, and permission string (e.g., R, W, D, RW, RWD, or - for deny all)."})
        return
    }

    perms := parsePermissions(strings.ToUpper(req.ACLPerm))
    role := strings.ToLower(req.ACLRole)

    keyACLLock.Lock()
    defer keyACLLock.Unlock()

    acl, exists := keyACLs[req.Key]
    if !exists {
        acl = KeyACL{Roles: make(map[string]Permissions)}
    }
    
    if req.ACLPerm == "-" {
        delete(acl.Roles, role)
        if len(acl.Roles) == 0 {
            delete(keyACLs, req.Key) 
        }
        writeJSON(client.Socket, Response{Status: "OK", Op: "SET_ACL", Message: fmt.Sprintf("ACL for key '%s', role '%s' cleared.", req.Key, role)})
        return
    }

    acl.Roles[role] = perms
    keyACLs[req.Key] = acl
    log.Printf("🔑 ACL set by admin %s: Key=%s, Role=%s, Perms=%s", client.CurrentUser.Username, req.Key, role, req.ACLPerm)
    writeJSON(client.Socket, Response{
        Status: "OK", 
        Op: "SET_ACL", 
        Message: fmt.Sprintf("ACL set for key '%s': Role '%s' granted permissions: R:%t, W:%t, D:%t.", req.Key, role, perms.Read, perms.Write, perms.Delete),
    })
}
func handleSetGroup(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "SET_GROUP requires admin privileges."})
        return
    }
    if req.GroupName == "" || req.Username == "" {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: "SET_GROUP requires groupName and username."})
        return
    }
    
    groupName := strings.ToLower(req.GroupName)
    username := req.Username

    authMutex.RLock()
    _, userExists := users[username]
    authMutex.RUnlock()
    if !userExists {
        writeJSON(client.Socket, Response{Status: "ERROR", Message: fmt.Sprintf("User '%s' does not exist.", username)})
        return
    }

    groupLock.Lock()
    defer groupLock.Unlock()

    usersInGroup, exists := userGroups[groupName]
    if !exists {
        usersInGroup = []string{}
    }

    isMember := false
    memberIndex := -1
    for i, u := range usersInGroup {
        if u == username {
            isMember = true
            memberIndex = i
            break
        }
    }
    
    if !isMember {
        userGroups[groupName] = append(usersInGroup, username)
        log.Printf("👥 User '%s' added to group '%s'.", username, groupName)
        writeJSON(client.Socket, Response{Status: "OK", Op: "SET_GROUP", Message: fmt.Sprintf("User '%s' added to group '%s'.", username, groupName)})
        return
    } 

    if isMember {
        userGroups[groupName] = append(usersInGroup[:memberIndex], usersInGroup[memberIndex+1:]...)
        if len(userGroups[groupName]) == 0 {
             delete(userGroups, groupName)
        }
        log.Printf("❌ User '%s' removed from group '%s'.", username, groupName)
        writeJSON(client.Socket, Response{Status: "OK", Op: "SET_GROUP", Message: fmt.Sprintf("User '%s' removed from group '%s'.", username, groupName)})
    }
}

func handleRestart(client *ClientConnection, req Request) {
    if !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "Only administrators can restart the server."})
        return
    }
	log.Printf("🔄 Received RESTART command from client %v. Initiating shutdown and save...", client.ID)
	writeJSON(client.Socket, Response{
		Status:  "OK",
		Op:      "RESTART",
		Message: fmt.Sprintf("Server received restart command. Data will be saved to %s before terminating. Please restart the process.", *dumpFilenamePtr),
	})
	close(serverStopCh) 
}
func handleShutdown(client *ClientConnection, req Request) {
    if !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "Only administrators can shut down the server."})
        return
    }
	log.Printf("🛑 Received SHUTDOWN command from client %v. Initiating shutdown and save...", client.ID)
	writeJSON(client.Socket, Response{
		Status:  "OK",
		Op:      "SHUTDOWN",
		Message: fmt.Sprintf("Server received shutdown command. Data will be saved to %s before terminating.", *dumpFilenamePtr),
	})
	close(serverStopCh) 
}

func handleViewUsers(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Op: "VIEW_USERS", Message: "VIEW_USERS requires admin privileges."})
        return
    }

    authMutex.RLock()
    defer authMutex.RUnlock()

    userList := make([]map[string]interface{}, 0, len(users))
    for _, user := range users {
        userList = append(userList, map[string]interface{}{
            "username": user.Username,
            "role":     user.Role,
            "email":    user.UserEmail,
            "status":   ternary(user.Deleted, "DELETED", "ACTIVE"),
        })
    }
    
    writeJSON(client.Socket, Response{
        Status: "OK", 
        Op: "VIEW_USERS", 
        Results: userList,
        Message: fmt.Sprintf("Retrieved %d user profiles.", len(userList)),
    })
}

func handleViewGroups(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Op: "VIEW_GROUPS", Message: "VIEW_GROUPS requires admin privileges."})
        return
    }
    
    groupLock.RLock()
    defer groupLock.RUnlock()
    
    writeJSON(client.Socket, Response{
        Status: "OK",
        Op: "VIEW_GROUPS",
        Results: userGroups,
        Message: fmt.Sprintf("Retrieved %d group definitions.", len(userGroups)),
    })
}

func handleViewRoles(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Op: "VIEW_ROLES", Message: "VIEW_ROLES requires admin privileges."})
        return
    }

    writeJSON(client.Socket, Response{
        Status: "OK",
        Op: "VIEW_ROLES",
        Results: availableRoles,
        Message: fmt.Sprintf("Retrieved %d defined roles.", len(availableRoles)),
    })
}

func handleViewACL(client *ClientConnection, req Request) {
    if !isAuthenticated(client) || !hasPermission(client, "admin") {
        writeJSON(client.Socket, Response{Status: "FORBIDDEN", Op: "VIEW_ACL", Message: "VIEW_ACL requires admin privileges."})
        return
    }

    keyACLLock.RLock()
    defer keyACLLock.RUnlock()

    if req.Key != "" {
        // View ACL for a specific key
        acl, exists := keyACLs[req.Key]
        if !exists {
            writeJSON(client.Socket, Response{Status: "NOT_FOUND", Op: "VIEW_ACL", Key: req.Key, Message: fmt.Sprintf("No explicit ACL found for key '%s'.", req.Key)})
            return
        }
        writeJSON(client.Socket, Response{
            Status: "OK",
            Op: "VIEW_ACL",
            Key: req.Key,
            Results: acl,
            Message: fmt.Sprintf("ACL retrieved for key '%s'.", req.Key),
        })
    } else {
        // View all keys with ACLs set
        writeJSON(client.Socket, Response{
            Status: "OK",
            Op: "VIEW_ACL",
            Results: keyACLs,
            Message: fmt.Sprintf("Retrieved all %d keys with explicit ACLs.", len(keyACLs)),
        })
    }
}

func ternary(condition bool, trueVal, falseVal interface{}) interface{} {
    if condition {
        return trueVal
    }
    return falseVal
}

// // handleRequest is the main handler for DB operations, integrating ACL checks
// func handleRequest(client *ClientConnection, req Request) {
// 	var resp Response

//     if !isAuthenticated(client) {
//         writeJSON(client.Socket, Response{Status: "UNAUTHORIZED", Message: "Operation requires a successful login."})
//         return
//     }

// 	switch req.Op {
// 	case "BROADCAST":
//         if !hasPermission(client, "user") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "BROADCAST requires 'user' role or higher."})
//             return
//         }
//         resp = Response{Status: "OK", Op: "BROADCAST", Message: "Broadcast simulated."}

// 	case "SETID":
//         resp = Response{Status: "OK", Op: "SETID", Message: "ID update simulated."}

// 	case "SET":
//         if !checkPermissionForKey(client, req.Key, "W") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: fmt.Sprintf("Write permission denied for key '%s'.", req.Key)})
//             return
//         }
// 		store.Lock.Lock()
// 		store.Data[req.Key] = req.Value
// 		store.Lock.Unlock()
// 		resp = Response{Status: "OK", Op: "SET", Key: req.Key}

// 	case "GET":
//         if !checkPermissionForKey(client, req.Key, "R") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: fmt.Sprintf("Read permission denied for key '%s'.", req.Key)})
//             return
//         }
// 		store.Lock.RLock()
// 		val, exists := store.Data[req.Key]
// 		store.Lock.RUnlock()
// 		if exists {
// 			resp = Response{Status: "OK", Op: "GET", Key: req.Key, Value: val}
// 		} else {
// 			resp = Response{Status: "NOT_FOUND", Op: "GET", Key: req.Key}
// 		}

// 	case "DELETE":
//         if !checkPermissionForKey(client, req.Key, "D") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: fmt.Sprintf("Delete permission denied for key '%s'.", req.Key)})
//             return
//         }
// 		store.Lock.Lock()
// 		delete(store.Data, req.Key)
// 		store.Lock.Unlock()
// 		resp = Response{Status: "OK", Op: "DELETE", Key: req.Key}

// 	case "DUMP":
//         if !hasPermission(client, "admin") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "DUMP operation requires 'admin' role."})
//             return
//         }
//         resp = Response{Status: "OK", Op: "DUMP", Data: "Dump simulated."}

// 	case "DUMPTOFILE":
//         if !hasPermission(client, "admin") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "DUMPTOFILE operation requires 'admin' role."})
//             return
//         }
// 		dumpStoreToFile(*dumpFilenamePtr)
// 		resp = Response{Status: "OK", Op: "DUMPTOFILE", Message: fmt.Sprintf("Dump executed to %s.", *dumpFilenamePtr)}

// 	case "SEARCH", "SEARCHKEY":
//         if !hasPermission(client, "user") {
//             writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "Search operations require 'user' role or higher."})
//             return
//         }
//         resp = Response{Status: "OK", Op: req.Op, Results: "Search simulated."}

// 	default:
// 		resp = Response{Status: "ERROR", Message: "Unknown operation"}
// 	}

// 	writeJSON(client.Socket, resp)
// }

func handleRequest(client *ClientConnection, req Request) {
	var resp Response

    if !isAuthenticated(client) {
        writeJSON(client.Socket, Response{Status: "UNAUTHORIZED", Message: "Operation requires a successful login."})
        return
    }

	switch req.Op {
	case "BROADCAST":
        if !hasPermission(client, "user") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "BROADCAST requires 'user' role or higher."})
            return
        }
        // BROADCAST logic remains the same (simulated in the provided code)
        resp = Response{Status: "OK", Op: "BROADCAST", Message: "Broadcast simulated."}

	case "SETID":
        resp = Response{Status: "OK", Op: "SETID", Message: "ID update simulated."}

	case "SET":
        if !checkPermissionForKey(client, req.Key, "W") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: fmt.Sprintf("Write permission denied for key '%s'.", req.Key)})
            return
        }
		store.Lock.Lock()
		store.Data[req.Key] = req.Value
		store.Lock.Unlock()
		resp = Response{Status: "OK", Op: "SET", Key: req.Key}

	case "GET":
        if !checkPermissionForKey(client, req.Key, "R") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: fmt.Sprintf("Read permission denied for key '%s'.", req.Key)})
            return
        }
		store.Lock.RLock()
		val, exists := store.Data[req.Key]
		store.Lock.RUnlock()
		if exists {
			resp = Response{Status: "OK", Op: "GET", Key: req.Key, Value: val}
		} else {
			resp = Response{Status: "NOT_FOUND", Op: "GET", Key: req.Key}
		}

	case "DELETE":
        if !checkPermissionForKey(client, req.Key, "D") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: fmt.Sprintf("Delete permission denied for key '%s'.", req.Key)})
            return
        }
		store.Lock.Lock()
		delete(store.Data, req.Key)
		store.Lock.Unlock()
		resp = Response{Status: "OK", Op: "DELETE", Key: req.Key}

	case "DUMP":
        // DUMP to Console
        if !hasPermission(client, "admin") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "DUMP operation requires 'admin' role."})
            return
        }
        store.Lock.RLock()
        dumpData := store.Data 
        store.Lock.RUnlock()
        
        // Return the entire database content in the Value field
        resp = Response{Status: "OK", Op: "DUMP", Value: dumpData, Message: "Database content returned."}

	case "DUMPTOFILE":
        // DUMP to File (on server)
        if !hasPermission(client, "admin") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "DUMPTOFILE operation requires 'admin' role."})
            return
        }
        
        filename := req.Filename
        if filename == "" {
            filename = *dumpFilenamePtr 
        }
        
        dumpStoreToFile(filename) 
        
		resp = Response{Status: "OK", Op: "DUMPTOFILE", Message: fmt.Sprintf("Dump executed to %s on the server.", filename)}

	case "SEARCH", "SEARCHKEY":
        if !hasPermission(client, "user") {
            writeJSON(client.Socket, Response{Status: "FORBIDDEN", Message: "Search operations require 'user' role or higher."})
            return
        }
        resp = Response{Status: "OK", Op: req.Op, Results: "Search simulated."}

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
	caCert, err := os.ReadFile(*caCertPtr)
	if err != nil {
		log.Fatalf("Error reading CA cert (%s): %v", *caCertPtr, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*clientCertPtr, *clientKeyPtr)
	if err != nil {
		log.Fatalf("Error reading client certs: %v", err)
	}

	config := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}
    
	lowercaseHost := strings.ToLower(*hostPtr)
	prompt := fmt.Sprintf("jsondb@%s:%s> ", lowercaseHost, port)

	conn, err := tls.Dial("tcp", *hostPtr+":"+port, config)
	if err != nil {
		log.Fatalf("Connection Setup Error: %v", err)
	}
	defer conn.Close()

	fmt.Printf("\n✅ Connected to DB Shell at %s:%s\n", *hostPtr, port)

	// Async Reader
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			text := scanner.Text()
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(text), &resp); err == nil {
				op, ok := resp["op"].(string)
				
				if _, sOk := resp["status"].(string); sOk && op == "BROADCAST" {
					fmt.Printf("\n📢 [Client %v]: %v\n%s", resp["senderId"], resp["message"], prompt)
				} else if ok && (op == "SHUTDOWN" || op == "RESTART") {
					pretty, _ := json.MarshalIndent(resp, "", "  ")
					fmt.Printf("<- %s\n", string(pretty))
					fmt.Printf("Server initiated %s. Disconnecting.\n", op)
					os.Exit(0) 
				} else {
					pretty, _ := json.MarshalIndent(resp, "", "  ")
					fmt.Printf("\n<- %s\n%s", string(pretty), prompt)
				}
			} else {
				fmt.Printf("\n<- %s\n%s", text, prompt)
			}
		}
		fmt.Println("\nDisconnected.")
		os.Exit(0)
	}()

	// Input Loop
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print(prompt)
	for scanner.Scan() {
		line := scanner.Text()
		cmd, err := parseShellInput(line)
		if err != nil {
			if err.Error() != "empty" {
				fmt.Println("Error:", err)
			}
			fmt.Print(prompt)
			continue
		}
		if cmd.Op == "EXIT" {
			break
		}
		if cmd.Op == "HELP" {
			printHelp()
			fmt.Print(prompt)
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
	case "EXIT", "HELP", "DUMP", "DUMPTOFILE", "SHUTDOWN", "RESTART", "LOGOUT", "VIEW_USERS", "VIEW_GROUPS", "VIEW_ROLES":
		return Request{Op: op}, nil
    case "LOGIN":
        if len(parts) < 3 {
            return Request{}, fmt.Errorf("usage: LOGIN <username> <password>")
        }
        return Request{Op: op, Username: parts[1], Password: parts[2]}, nil
    case "CHANGE_PASSWORD":
        if len(parts) < 3 {
            return Request{}, fmt.Errorf("usage: CHANGE_PASSWORD <current_password> <new_password>")
        }
        return Request{Op: op, Password: parts[1], NewPassword: parts[2]}, nil
    case "ADD_USER":
        if len(parts) < 5 {
            return Request{}, fmt.Errorf("usage: ADD_USER <username> <password> <email> <role>")
        }
        return Request{Op: op, Username: parts[1], Password: parts[2], UserEmail: parts[3], Role: parts[4]}, nil
    case "REMOVE_USER":
        if len(parts) < 2 {
            return Request{}, fmt.Errorf("usage: REMOVE_USER <username>")
        }
        return Request{Op: op, Username: parts[1]}, nil
    case "SET_ACL":
        if len(parts) < 4 {
            return Request{}, fmt.Errorf("usage: SET_ACL <key> <role> <permissions (R, W, D, RW, RWD, -)>")
        }
        return Request{Op: op, Key: parts[1], ACLRole: parts[2], ACLPerm: parts[3]}, nil
    case "SET_GROUP":
        if len(parts) < 3 {
            return Request{}, fmt.Errorf("usage: SET_GROUP <group_name> <username>")
        }
        return Request{Op: op, GroupName: parts[1], Username: parts[2]}, nil
    case "VIEW_ACL":
        req := Request{Op: op}
        if len(parts) > 1 {
            req.Key = parts[1]
        }
        return req, nil
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
		if err := json.Unmarshal([]byte(valStr), &val); err != nil {
			if num, err := strconv.ParseFloat(valStr, 64); err == nil {
				val = num
			} else {
				val = valStr
			}
		}
		return Request{Op: op, Key: parts[1], Value: val}, nil
	default:
		return Request{}, fmt.Errorf("unknown operation")
	}
}

func printHelp() {
	fmt.Println("--- DB Commands (Key-Level ACLs Apply) ---")
	fmt.Println("  SET <key> <value>            : Requires 'W' permission on <key>.")
    fmt.Println("  GET <key>                    : Requires 'R' permission on <key>.")
    fmt.Println("  DELETE <key>                 : Requires 'D' permission on <key>.")
    fmt.Println("  SEARCH <term>                : Requires 'user' role or higher.")
    fmt.Println("  SEARCHKEY <term>             : Requires 'user' role or higher.")
	fmt.Println("  BROADCAST <message>          : Requires 'user' role or higher.")
    fmt.Println("  SETID <newId>                : Requires login.")
    fmt.Println()
    fmt.Println("--- Security & Server Management (Admin Role) ---")
    fmt.Println("  ADD_USER <uName> <pwd> <email> <role> : Create a new user.")
    fmt.Println("  REMOVE_USER <uName>          : Soft-delete a user.")
    fmt.Println("  SET_ACL <key> <role> <perms> : Set Read/Write/Delete permissions for a role on a key.")
    fmt.Println("  SET_GROUP <group> <uName>    : Add/Remove a user from a group.")
    fmt.Println("  DUMP, DUMPTOFILE, SHUTDOWN, RESTART : Server management.")
    fmt.Println()
    fmt.Println("--- VIEW/AUDIT Commands (Admin Role) ---")
    fmt.Println("  VIEW_USERS                   : Show all user profiles (username, role, status).")
    fmt.Println("  VIEW_GROUPS                  : Show all groups and their members.")
    fmt.Println("  VIEW_ROLES                   : Show all predefined roles.")
    fmt.Println("  VIEW_ACL [key]               : Show ACLs for a specific key, or all keys if [key] is omitted.")
    fmt.Println()
    fmt.Println("--- Authentication & Client Commands ---")
    fmt.Println("  LOGIN <uName> <pwd>          : Authenticate and start session. (Session bound to IP/Port)")
    fmt.Println("  LOGOUT                       : End current session.")
    fmt.Println("  CHANGE_PASSWORD <curr> <new> : Change your own password.")
    fmt.Println("  EXIT / HELP                  : Client commands.")
}