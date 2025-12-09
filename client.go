package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	// "net"	
	"os"
	"strconv"
	"strings"
)

// --- Configuration ---
const (
	HOST         = "localhost"
	DEFAULT_PORT = "9999"
	SERVER_CERT  = "ca.crt" // CA to verify server
	CLIENT_KEY   = "client.key"
	CLIENT_CERT  = "client.crt"
)

// --- Structures ---
type Command struct {
	Op       string                 `json:"op"`
	Key      string                 `json:"key,omitempty"`
	Value    interface{}            `json:"value,omitempty"`
	Term     string                 `json:"term,omitempty"`
	NewID    string                 `json:"newId,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Filename string                 `json:"filename,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// Helper to parse input similar to Node.js logic
func parseInput(input string) (Command, error) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return Command{}, fmt.Errorf("empty")
	}

	op := strings.ToUpper(parts[0])
	var arg1 string
	if len(parts) > 1 {
		arg1 = parts[1]
	}

	// Simple Commands
	if op == "DUMP" || op == "EXIT" || op == "HELP" || op == "DUMPTOFILE" {
		return Command{Op: op}, nil
	}

	if op == "BROADCAST" {
		if len(parts) < 2 {
			return Command{}, fmt.Errorf("BROADCAST requires a message")
		}
		// Rejoin the rest of the string
		msg := strings.TrimSpace(strings.TrimPrefix(input, parts[0]))
		return Command{Op: op, Message: msg}, nil
	}

	if op == "SETID" {
		if arg1 == "" {
			return Command{}, fmt.Errorf("SETID requires a new ID")
		}
		return Command{Op: op, NewID: arg1}, nil
	}

	if op == "LOAD" || op == "INIT" {
		if arg1 == "" && op == "INIT" {
			return Command{Op: op}, nil
		}
		if arg1 == "" {
			return Command{}, fmt.Errorf("%s requires data or filename", op)
		}

		rest := strings.TrimSpace(strings.TrimPrefix(input, parts[0]))
		
		// Attempt to detect if it's inline JSON
		if strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(rest), &data); err != nil {
				return Command{}, fmt.Errorf("invalid inline JSON: %v", err)
			}
			return Command{Op: op, Data: data}, nil
		}
		return Command{Op: op, Filename: rest}, nil
	}

	if op == "SEARCH" || op == "SEARCHKEY" {
		if arg1 == "" {
			return Command{}, fmt.Errorf("%s requires a term", op)
		}
		return Command{Op: op, Term: arg1}, nil
	}

	// CRUD
	validOps := map[string]bool{"SET": true, "GET": true, "DELETE": true}
	if !validOps[op] {
		return Command{}, fmt.Errorf("unknown operation: %s", op)
	}

	key := arg1
	if key == "" {
		return Command{}, fmt.Errorf("%s requires a key", op)
	}

	if op == "SET" {
		// Complex parsing to extract value after key
		prefix := parts[0] + " " + parts[1]
		valStr := strings.TrimSpace(strings.TrimPrefix(input, prefix))
		// Handle sloppy spacing in prefix matching
		if valStr == input {
			// Fallback if multiple spaces were used
			partsIndex := strings.Index(input, key)
			if partsIndex != -1 {
				valStr = strings.TrimSpace(input[partsIndex+len(key):])
			}
		}

		if valStr == "" {
			return Command{}, fmt.Errorf("SET requires a value")
		}

		var val interface{}
		// Try parsing as JSON first
		if err := json.Unmarshal([]byte(valStr), &val); err != nil {
			// If not JSON, treat as string (quote it to make it valid JSON string)
			// Or check if it is a number
			if _, errNum := strconv.ParseFloat(valStr, 64); errNum == nil {
				json.Unmarshal([]byte(valStr), &val)
			} else {
				val = valStr // Treat as raw string
			}
		}
		return Command{Op: op, Key: key, Value: val}, nil
	}

	return Command{Op: op, Key: key}, nil
}

func main() {
	port := DEFAULT_PORT
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// Load CA to verify server
	caCert, err := os.ReadFile(SERVER_CERT)
	if err != nil {
		log.Fatalf("Error reading server cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load Client Cert/Key
	cert, err := tls.LoadX509KeyPair(CLIENT_CERT, CLIENT_KEY)
	if err != nil {
		log.Fatalf("Error reading client keypair: %v", err)
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

	fmt.Printf("\n✅ Securely connected to server at %s:%s. Type 'help' for usage.\n", HOST, port)

	// Channel to signal exit
	done := make(chan struct{})

	// Goroutine: Read from Server
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			text := scanner.Text()
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(text), &resp); err == nil {
				if status, ok := resp["status"].(string); ok && status == "BROADCAST" {
					fmt.Printf("\n BROADCAST from [Client %v]: %v\njsondb@%s:%s> ", resp["senderId"], resp["message"], HOST, port)
				} else {
					fmt.Println("Response::")
					pretty, _ := json.MarshalIndent(resp, "", "    ")
					fmt.Println(string(pretty))
					fmt.Printf("jsondb@%s:%s> ", HOST, port)
				}
			} else {
				fmt.Printf("\n<- Raw: %s\njsondb@%s:%s> ", text, HOST, port)
			}
		}
		fmt.Println("\nConnection closed by server.")
		close(done)
		os.Exit(0)
	}()

	// Main Loop: Read from Stdin
	inputScanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("jsondb@%s:%s> ", HOST, port)

	for inputScanner.Scan() {
		line := inputScanner.Text()
		cmd, err := parseInput(line)

		if cmd.Op == "EXIT" {
			break
		}
		if cmd.Op == "HELP" {
			printHelp()
			fmt.Printf("jsondb@%s:%s> ", HOST, port)
			continue
		}
		if err != nil {
			if err.Error() != "empty" {
				fmt.Println("Error:", err)
			}
			fmt.Printf("jsondb@%s:%s> ", HOST, port)
			continue
		}

		// Send to server
		bytes, _ := json.Marshal(cmd)
		conn.Write(append(bytes, '\n'))
	}
}

func printHelp() {
	fmt.Println("Available Commands:")
	fmt.Println("  SET <key> <value>      - Create/Update a key.")
	fmt.Println("  GET <key>              - Read a key.")
	fmt.Println("  DELETE <key>           - Delete a key.")
	fmt.Println("  LOAD <json|file>       - Merge data.")
	fmt.Println("  INIT <json|file>       - Replace data.")
	fmt.Println("  SEARCH <term>          - Search keys and values.")
	fmt.Println("  SEARCHKEY <term>       - Search keys only.")
	fmt.Println("  BROADCAST <msg>        - Message all clients.")
	fmt.Println("  DUMP                   - Show all data.")
	fmt.Println("  DUMPTOFILE             - Write data to server file.")
	fmt.Println("  SETID <new_id>         - Change client ID.")
	fmt.Println("  EXIT                   - Quit.")
}