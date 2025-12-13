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
	ClientID     string // Server assigned ID (e.g., 1:127.0.0.1:54321)
	RemoteAddr   string // Server address (e.g., localhost:9999)
	Scanner      *bufio.Scanner
}

// Request structure (matches server's Request struct)
type Request struct {
	Op       string      `json:"op"`
	Key      string      `json:"key,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Filename string      `json:"filename,omitempty"`
	Term     interface{} `json:"term,omitempty"`
	Message  string      `json:"message,omitempty"`
	NewID    interface{} `json:"newId,omitempty"`
}

// Response structure (matches server's Response struct)
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
	}
}

// --- Blocking ID Acquisition ---

// acquireClientID blocks until the first response (STATUS) is received and processed.
func acquireClientID(ctx *ClientContext) error {
	reader := bufio.NewReader(ctx.ClientSocket)
    
    // Set a timeout for reading the initial response (e.g., 5 seconds)
    ctx.ClientSocket.SetReadDeadline(time.Now().Add(5 * time.Second))

	rawResp, err := reader.ReadBytes('\n')
	if err != nil {
        ctx.ClientSocket.SetReadDeadline(time.Time{}) // Clear deadline
		return fmt.Errorf("error reading initial server response: %w", err)
	}
    
    ctx.ClientSocket.SetReadDeadline(time.Time{}) // Clear deadline

	var resp Response
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return fmt.Errorf("invalid JSON in initial server response: %w", err)
	}

	// CRITICAL: Check for the expected STATUS message
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

// displayPrompt constructs and displays the shell prompt (jsondb@ServerHost:ServerPort>)
func (c *ClientContext) displayPrompt() {
	// CHANGED: Simplified prompt to show only the server address
	fmt.Printf("jsondb@%s> ", c.RemoteAddr)
}

// --- Communication ---

func (c *ClientContext) sendRequest(req Request) {
	data, err := json.Marshal(req)
	if err != nil {
		log.Println("Error marshaling request:", err)
		return
	}
	c.ClientSocket.Write(append(data, '\n'))
}

// handleResponse parses and displays the server's JSON response
func (c *ClientContext) handleResponse(rawResp []byte) {
	var resp Response
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		fmt.Printf(" [Server] Invalid JSON response: %s\n", rawResp)
		return
	}
    
    // If the ID is updated via SETID, update ctx.ClientID
    if resp.SenderId != nil {
        if idStr, ok := resp.SenderId.(string); ok && idStr != "" {
            c.ClientID = idStr
        }
    }

	// Print the server response based on status
	switch resp.Status {
	case "OK":
		if resp.Op == "GET" {
			fmt.Printf(" [OK] Key: %s, Value: %v\n", resp.Key, resp.Value)
		} else if resp.Op == "DUMP" {
			data, _ := json.MarshalIndent(resp.Data, "", "  ")
			fmt.Printf(" [OK] Full Store Dump:\n%s\n", data)
		} else if resp.Results != nil {
			if resMap, ok := resp.Results.(map[string]interface{}); ok && len(resMap) > 0 {
				results, _ := json.MarshalIndent(resMap, "", "  ")
				fmt.Printf(" [OK] Search Results:\n%s\n", results)
			} else {
				fmt.Printf(" [OK] Search completed, 0 results.\n")
			}
		} else {
			fmt.Printf(" [OK] %s\n", resp.Message)
		}
	case "NOT_FOUND":
		fmt.Printf(" [NOT FOUND] Key: %s\n", resp.Key)
	case "ERROR":
		fmt.Printf(" [ERROR] %s\n", resp.Message)
	case "BROADCAST":
		fmt.Printf("\n[BROADCAST from %v] %s\n", resp.SenderId, resp.Message)
	default:
        // Don't print the initial STATUS message, but log other unhandled statuses
        if resp.Status != "STATUS" {
		    fmt.Printf(" [STATUS: %s] %s\n", resp.Status, resp.Message)
        }
	}
}

// processInput handles command parsing from stdin
func processInput(input string, ctx *ClientContext) (Request, bool) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return Request{}, false
	}

	op := strings.ToUpper(parts[0])
	req := Request{Op: op}

	switch op {
	case "EXIT", "QUIT":
		return req, true 
	case "MYADDR":
		// RE-ADDED: Client-side command to display connection details
		fmt.Printf("Client ID: %s\n", ctx.ClientID)
		
		idParts := strings.Split(ctx.ClientID, ":")
		if ctx.ClientID == "N/A" {
			fmt.Printf("  Status: ID not yet received from server.\n")
		} else if len(idParts) >= 3 {
            // Server ID format is typically N:IP:PORT or NAME:IP:PORT
			idPart := idParts[0]
			ipPart := idParts[len(idParts)-2]
			portPart := idParts[len(idParts)-1]
            
            // Format output as requested
			fmt.Printf("  clientid > %s\n", idPart)
			fmt.Printf("  clientip > %s\n", ipPart)
			fmt.Printf("  clientport > %s\n", portPart)
		} else {
			fmt.Printf("  Status: ID received, but format is irregular: %s\n", ctx.ClientID)
		}
		return Request{}, false // Do not send anything to the server
	case "SET":
		if len(parts) < 3 {
			fmt.Println("Usage: SET <key> <value_in_json_format>")
			return req, false
		}
		key := parts[1]
		valueStr := strings.Join(parts[2:], " ")
		
		var value interface{}
		if err := json.Unmarshal([]byte(valueStr), &value); err != nil {
			value = valueStr
		}
		req.Key = key
		req.Value = value
	case "GET", "DELETE":
		if len(parts) != 2 {
			fmt.Printf("Usage: %s <key>\n", op)
			return req, false
		}
		req.Key = parts[1]
	case "SEARCH", "SEARCHKEY":
		if len(parts) != 2 {
			fmt.Printf("Usage: %s <search_term>\n", op)
			return req, false
		}
		req.Term = parts[1]
	case "BROADCAST":
		if len(parts) < 2 {
			fmt.Println("Usage: BROADCAST <message>")
			return req, false
		}
		req.Message = strings.Join(parts[1:], " ")
	case "SETID":
		if len(parts) != 2 {
			fmt.Println("Usage: SETID <new_name>")
			return req, false
		}
		req.NewID = parts[1]
    case "DUMP", "DUMPTOFILE":
        // DUMP and DUMPTOFILE need no further arguments
	default:
		fmt.Printf("Unknown operation: %s\n", op)
		return req, false
	}

	return req, false
}

// --- Main Loop ---

func main() {
	setupFlags()

	// Connect and get context
	ctx := connectToServer()
	defer ctx.ClientSocket.Close()

    fmt.Printf("Connected securely to %s. Waiting for initial ID...\n", ctx.RemoteAddr)
    
    // BLOCKING CALL: Acquire the client ID before starting the interactive loop.
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
			
			// Process all incoming responses (including broadcasts and SETID confirmations)
			ctx.handleResponse(rawResp)

			// Redisplay prompt after async response like BROADCAST or SETID
			if strings.Contains(string(rawResp), `"BROADCAST"`) || strings.Contains(string(rawResp), `"SETID"`) {
				ctx.displayPrompt()
			}
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
		req, shouldQuit := processInput(input, ctx) 

		if shouldQuit {
			fmt.Println("Exiting client.")
			return
		}

		if req.Op != "" {
			ctx.sendRequest(req)
		}
	}
}