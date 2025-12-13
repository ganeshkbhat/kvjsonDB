package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// --- Configuration Variables (Client Flags) ---
var (
	// Network
	host     *string
	port     *string
	// Security (mTLS)
	certFile *string
	keyFile  *string
	serverCA *string
)

// ClientContext holds necessary data for the shell
type ClientContext struct {
	ClientSocket *tls.Conn
	ClientID     string 
	RemoteAddr   string 
	Scanner      *bufio.Scanner
    
    // Channel to synchronize synchronous command responses
    responseChan chan bool 
}

// Request structure (The data sent must conform to this JSON structure)
type Request struct {
	Op       string      `json:"op"`
	Key      string      `json:"key,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Filename string      `json:"filename,omitempty"`
	Term     interface{} `json:"term,omitempty"`
	Message  string      `json:"message,omitempty"`
	NewID    interface{} `json:"newId,omitempty"`
}

// Response structure (The data received will always conform to this JSON structure)
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

// --- Initialization ---

func setupFlags() {
	host = flag.String("h", "localhost", "Server Host (long: --host).")
	port = flag.String("p", "9999", "Server Port (long: --port).")
	flag.StringVar(host, "host", "localhost", "Server Host (short: -h).")
	flag.StringVar(port, "port", "9999", "Server Port (short: -p).")

	certFile = flag.String("c", "client.crt", "Client Cert Path (long: --cert).")
	keyFile = flag.String("k", "client.key", "Client Private Key Path (long: --key).")
	serverCA = flag.String("ca", "ca.crt", "Root CA Cert Path (long: --ca) to verify server.")
	flag.StringVar(serverCA, "ca-cert", "ca.crt", "Root CA Certificate Path (short: -ca) to verify server.")

	flag.Parse()
}

func connectToServer() *ClientContext {
	addr := *host + ":" + *port

	// 1. Load Client Cert/Key
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Error loading client key pair %s/%s: %v", *certFile, *keyFile, err)
	}

	// 2. Load CA to verify the Server
	caCert, err := os.ReadFile(*serverCA)
	if err != nil {
		log.Fatalf("Error reading server CA cert %s: %v", *serverCA, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false, 
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", addr, err)
	}

	return &ClientContext{
		ClientSocket: conn,
		ClientID:     "N/A", 
		RemoteAddr:   addr,
		Scanner:      bufio.NewScanner(os.Stdin),
        responseChan: make(chan bool, 1),
	}
}

// --- Blocking ID Acquisition ---

func acquireClientID(ctx *ClientContext) error {
	reader := bufio.NewReader(ctx.ClientSocket)
    
    ctx.ClientSocket.SetReadDeadline(time.Now().Add(5 * time.Second))

	rawResp, err := reader.ReadBytes('\n')
	if err != nil {
        ctx.ClientSocket.SetReadDeadline(time.Time{})
		return fmt.Errorf("error reading initial server response: %w", err)
	}
    
    ctx.ClientSocket.SetReadDeadline(time.Time{})

	var resp Response
    // Enforce JSON structure on initial response
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return fmt.Errorf("invalid JSON in initial server response: %w", err)
	}

	if resp.Status == "STATUS" && resp.SenderId != nil {
		if idStr, ok := resp.SenderId.(string); ok && idStr != "" {
			ctx.ClientID = idStr
			log.Printf("Client ID set successfully to: %s", ctx.ClientID)
			return nil
		}
	}
    
	return fmt.Errorf("initial server response was not a valid STATUS message. Status: %s", resp.Status)
}

// --- Prompt Handling ---

func (c *ClientContext) displayPrompt() {
	fmt.Printf("jsondb@%s> ", c.RemoteAddr)
}

// --- Communication ---

// sendRequest marshals the Request struct to JSON and sends it.
func (c *ClientContext) sendRequest(req Request) {
	data, err := json.Marshal(req)
	if err != nil {
		log.Println("Error marshaling request:", err)
		return
	}
    // All client output is a single JSON structure followed by a newline.
	c.ClientSocket.Write(append(data, '\n'))
}

// handleResponse parses and displays the server's JSON response
func (c *ClientContext) handleResponse(rawResp []byte) {
	var resp Response
    // Enforce JSON structure on all incoming responses
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		fmt.Printf("\n [Server] Invalid JSON response: %s\n", rawResp)
        select {
        case c.responseChan <- true:
        default:
        }
		return
	}
    
    if resp.SenderId != nil {
        if idStr, ok := resp.SenderId.(string); ok && idStr != "" {
            c.ClientID = idStr
        }
    }
    
	switch resp.Status {
	case "OK":
		switch resp.Op {
		case "GET":
			// Output GET data prettily
			if resp.Value != nil {
				data, _ := json.MarshalIndent(resp.Value, "", "  ")
				fmt.Printf("%s\n", data)
			} else {
				fmt.Printf("null\n")
			}
		case "DUMP":
			data, _ := json.MarshalIndent(resp.Data, "", "  ")
			fmt.Printf("%s\n", data)
		case "SEARCH", "SEARCHKEY":
			if resMap, ok := resp.Results.(map[string]interface{}); ok && len(resMap) > 0 {
				results, _ := json.MarshalIndent(resMap, "", "  ")
				fmt.Printf("%s\n", results)
			} else {
				fmt.Printf("Search completed, 0 results.\n")
			}
        case "DUMPTOFILE", "SETID", "LOAD", "INIT":
            if resp.Message != "" {
                fmt.Printf("[INFO] %s\n", resp.Message)
            }
		}

	case "NOT_FOUND":
		fmt.Printf("[ERROR] Key not found: %s\n", resp.Key)
	case "ERROR":
		fmt.Printf("[ERROR] %s\n", resp.Message)
        
	default:
        // Handle STATUS messages or unexpected responses
        if resp.Status != "STATUS" {
		    fmt.Printf("[STATUS: %s] %s\n", resp.Status, resp.Message)
        }
	}
    
    // Always signal completion for a synchronous command
    select {
    case c.responseChan <- true:
    default:
    }
}

// processInput handles command parsing from stdin and constructs the JSON Request
func processInput(input string, ctx *ClientContext) (Request, bool, bool) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return Request{}, false, false
	}

	op := strings.ToUpper(parts[0])
	req := Request{Op: op}
    
    isServerCommand := true

	switch op {
	case "EXIT", "QUIT":
        isServerCommand = false
		return req, true, false
	case "MYADDR":
        isServerCommand = false
		fmt.Printf("Client ID: %s\n", ctx.ClientID)
		
		idParts := strings.Split(ctx.ClientID, ":")
		if ctx.ClientID == "N/A" {
			fmt.Printf("  Status: ID not yet received from server.\n")
		} else if len(idParts) >= 3 {
			idPart := idParts[0]
			ipPart := idParts[len(idParts)-2]
			portPart := idParts[len(idParts)-1]
            
			fmt.Printf("  clientid > %s\n", idPart)
			fmt.Printf("  clientip > %s\n", ipPart)
			fmt.Printf("  clientport > %s\n", portPart)
		} else {
			fmt.Printf("  Status: ID received, but format is irregular: %s\n", ctx.ClientID)
		}
        fmt.Println() 
		return Request{}, false, false

	case "SET":
		if len(parts) < 3 {
			fmt.Println("Usage: SET <key> <value_in_json_format>")
			return req, false, false
		}
		key := parts[1]
		valueStr := strings.Join(parts[2:], " ")
		
		var value interface{}
		if err := json.Unmarshal([]byte(valueStr), &value); err != nil {
			// Fallback to raw string if not valid JSON
			value = valueStr 
		}
		req.Key = key
		req.Value = value
        
	case "GET", "DELETE", "DUMPKEY": 
		if len(parts) != 2 {
			fmt.Printf("Usage: %s <key>\n", op)
			return req, false, false
		}
		req.Key = parts[1]
        
        if op == "DUMPKEY" {
            req.Op = "GET" // Map DUMPKEY command to server's GET operation
        }
        
	case "SEARCH", "SEARCHKEY":
		if len(parts) != 2 {
			fmt.Printf("Usage: %s <search_term>\n", op)
			return req, false, false
		}
		req.Term = parts[1]
        
	case "SETID":
		if len(parts) != 2 {
			fmt.Println("Usage: SETID <new_name>")
			return req, false, false
		}
		req.NewID = parts[1]
    
    case "LOAD":
        if len(parts) != 2 {
            fmt.Println("Usage: LOAD <filename>")
            return req, false, false
        }
        req.Filename = parts[1]
        
    case "DUMP", "DUMPTOFILE":
        if op == "DUMPTOFILE" && len(parts) > 1 {
            req.Filename = parts[1]
        } else if len(parts) != 1 && op == "DUMP" {
            fmt.Println("Usage: DUMP (no arguments)")
            return req, false, false
        }
    
	default:
        isServerCommand = false
		fmt.Printf("Unknown operation: %s\n", op)
		return Request{}, false, false
	}

	return req, false, isServerCommand
}

// --- Main Loop ---

func main() {
	setupFlags()

	// Connect and get context
	ctx := connectToServer()
	defer ctx.ClientSocket.Close()

    fmt.Printf("Connected securely to %s. Waiting for initial ID...\n", ctx.RemoteAddr)
    
    if err := acquireClientID(ctx); err != nil {
        log.Fatalf("Failed to synchronize ClientID with server: %v", err)
    }

    // Now, start the non-blocking response listener
	serverReader := bufio.NewReader(ctx.ClientSocket)
	go func() {
		for {
			rawResp, err := serverReader.ReadBytes('\n')
			if err != nil {
				log.Printf("Connection closed by server or error: %v", err)
				os.Exit(0)
				return
			}
			
			ctx.handleResponse(rawResp)
		}
	}()
    
    log.Println("ID synchronization complete. Starting shell.")
    
	// Main client input loop
	for {
		ctx.displayPrompt() 

		if !ctx.Scanner.Scan() {
			break 
		}
		
		input := ctx.Scanner.Text()
		req, shouldQuit, isServerCommand := processInput(input, ctx) 

		if shouldQuit {
			fmt.Println("Exiting client.")
			return
		}

		if req.Op != "" {
			ctx.sendRequest(req)
            
            // Wait for the handleResponse goroutine to process the response
            if isServerCommand {
                <-ctx.responseChan
            }
		}
	}
}