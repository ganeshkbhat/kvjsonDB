// package main

// import (
// 	"bufio"
// 	"crypto/sha1"
// 	"encoding/base64"
// 	"encoding/binary"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net"
// 	"os"
// 	"os/signal"
// 	"strings"
// 	"sync"
// 	"syscall"
// 	"time"
// )

// const (
// 	// WebSocket Opcodes
// 	opContinuation = 0x0
// 	opText         = 0x1
// 	opClose        = 0x8

// 	// WebSocket Protocol constants
// 	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// 	// Persistence constant (Always saves to encrypted XJSON for persistence)
// 	persistenceFile = "dictionary_dump.xjson"

// 	// Encryption key for .xjson files
// 	xorKey = 0xAA
// )

// // --- 1. Struct Definitions for Request/Response ---

// // Request structure for client commands
// type Request struct {
// 	Command string      `json:"command"`
// 	Key     string      `json:"key"`
// 	Value   interface{} `json:"value"`
// 	Search  string      `json:"search"`
// }

// // Response structure for server replies
// type Response struct {
// 	Success bool        `json:"success"`
// 	Message string      `json:"message"`
// 	Key     string      `json:"key,omitempty"`
// 	Value   interface{} `json:"value,omitempty"`
// 	Data    interface{} `json:"data,omitempty"`
// }

// // --- 2. Dictionary Management & Loaders ---

// // Dictionary struct to hold the data and protect it.
// type Dictionary struct {
// 	data map[string]interface{}
// 	mu   sync.RWMutex
// }

// // NewDictionary initializes and returns a new Dictionary instance.
// func NewDictionary() *Dictionary {
// 	return &Dictionary{
// 		data: make(map[string]interface{}),
// 	}
// }

// // xorEncryptDecrypt performs a simple XOR operation on data with a single byte key.
// // It is used here for "encryption" and "decryption".
// func xorEncryptDecrypt(data []byte, key byte) []byte {
// 	output := make([]byte, len(data))
// 	for i, b := range data {
// 		output[i] = b ^ key
// 	}
// 	return output
// }

// // loadFromJSON performs the standard JSON unmarshalling and merging.
// func (d *Dictionary) loadFromJSON(data []byte) error {
// 	var loadedData map[string]interface{}
// 	if err := json.Unmarshal(data, &loadedData); err != nil {
// 		return fmt.Errorf("error unmarshalling JSON data: %w", err)
// 	}

// 	// Merge loaded data into existing dictionary
// 	for k, v := range loadedData {
// 		d.data[k] = v
// 	}
// 	return nil
// }

// // loadFromXJSON decrypts the data using XOR, then attempts JSON unmarshalling and merging.
// func (d *Dictionary) loadFromXJSON(data []byte, filename string) error {
// 	log.Printf("Decrypting data from '%s' using XOR key 0x%X...", filename, xorKey)
// 	decryptedData := xorEncryptDecrypt(data, xorKey)
// 	return d.loadFromJSON(decryptedData)
// }

// // LoadFromFile attempts to load the dictionary data from a JSON or XJSON file.
// // It acts as a dispatcher based on the file extension.
// func (d *Dictionary) LoadFromFile(filename string) {
// 	d.mu.Lock()
// 	defer d.mu.Unlock()

// 	data, err := os.ReadFile(filename)
// 	if err != nil {
// 		if os.IsNotExist(err) {
// 			log.Printf("Loader file '%s' not found. Skipping load.", filename)
// 			return
// 		}
// 		log.Printf("Error reading file '%s': %v", filename, err)
// 		return
// 	}

// 	var loadErr error
// 	lowerFilename := strings.ToLower(filename)

// 	if strings.HasSuffix(lowerFilename, ".xjson") {
// 		loadErr = d.loadFromXJSON(data, filename)
// 	} else if strings.HasSuffix(lowerFilename, ".json") {
// 		loadErr = d.loadFromJSON(data)
// 	} else {
// 		log.Printf("Error: Unsupported file extension for '%s'. Must be .json or .xjson.", filename)
// 		return
// 	}

// 	if loadErr != nil {
// 		log.Printf("Error processing data from '%s': %v", filename, loadErr)
// 		return
// 	}

// 	log.Printf("Successfully loaded and merged %d keys from '%s'. Total keys: %d.", len(d.data), filename, len(d.data))
// }

// // SaveToFile dumps the entire dictionary data to a standard, unencrypted JSON file.
// // This is typically used for the client's manual SAVE command.
// func (d *Dictionary) SaveToFile(filename string) error {
// 	d.mu.RLock()
// 	defer d.mu.RUnlock()

// 	jsonBytes, err := json.MarshalIndent(d.data, "", "  ")
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal dictionary to JSON: %w", err)
// 	}

// 	if err := os.WriteFile(filename, jsonBytes, 0644); err != nil {
// 		return fmt.Errorf("failed to write data to file '%s': %w", filename, err)
// 	}

// 	log.Printf("Successfully saved %d keys to standard JSON file '%s'.", len(d.data), filename)
// 	return nil
// }

// // SaveToXJSON dumps the entire dictionary data to an XOR-encrypted XJSON file.
// // This is used for persistent server state save.
// func (d *Dictionary) SaveToXJSON(filename string) error {
// 	d.mu.RLock()
// 	defer d.mu.RUnlock()

// 	jsonBytes, err := json.MarshalIndent(d.data, "", "  ")
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal dictionary to JSON: %w", err)
// 	}

// 	log.Printf("Encrypting data for storage in '%s' using XOR key 0x%X...", filename, xorKey)
// 	encryptedData := xorEncryptDecrypt(jsonBytes, xorKey)

// 	if err := os.WriteFile(filename, encryptedData, 0644); err != nil {
// 		return fmt.Errorf("failed to write data to file '%s': %w", err)
// 	}

// 	log.Printf("Successfully saved %d keys to encrypted file '%s'.", len(d.data), filename)
// 	return nil
// }

// // recursiveSearch traverses nested map[string]interface{} and []interface{} structures
// // to check if any key or string/primitive value contains the searchTerm (case-insensitive).
// func recursiveSearch(value interface{}, searchTerm string) bool {
// 	if value == nil {
// 		return false
// 	}
	
// 	// Case 1: String (Base Case)
// 	if s, ok := value.(string); ok {
// 		return strings.Contains(strings.ToLower(s), searchTerm)
// 	}

// 	// Case 2: Map (Nested JSON object)
// 	if m, ok := value.(map[string]interface{}); ok {
// 		for key, nestedValue := range m {
// 			// Check if the map key itself contains the term
// 			if strings.Contains(strings.ToLower(key), searchTerm) {
// 				return true
// 			}
// 			// Recursive call on the nested value
// 			if recursiveSearch(nestedValue, searchTerm) {
// 				return true
// 			}
// 		}
// 		return false
// 	}

// 	// Case 3: Slice (Nested JSON array)
// 	if a, ok := value.([]interface{}); ok {
// 		for _, nestedValue := range a {
// 			if recursiveSearch(nestedValue, searchTerm) {
// 				return true
// 			}
// 		}
// 		return false
// 	}

// 	// Case 4: Primitives (Numbers, Booleans, etc.)
// 	// Convert primitive types to string and check
// 	s := strings.ToLower(fmt.Sprintf("%v", value))
// 	return strings.Contains(s, searchTerm)
// }

// // executeCommand processes the incoming Request and returns a structured Response.
// func (d *Dictionary) executeCommand(req Request) Response {
// 	command := strings.ToUpper(req.Command)
// 	key := req.Key

// 	switch command {
// 	case "SET":
// 		d.mu.Lock()
// 		defer d.mu.Unlock()
// 		if key == "" {
// 			return Response{Success: false, Message: "Key cannot be empty for SET."}
// 		}
// 		d.data[key] = req.Value
// 		return Response{Success: true, Message: fmt.Sprintf("Key '%s' set successfully.", key), Key: key, Value: req.Value}

// 	case "GET", "READ":
// 		d.mu.RLock()
// 		defer d.mu.RUnlock()
// 		if key == "" {
// 			return Response{Success: false, Message: "Key cannot be empty for GET/READ."}
// 		}
// 		if val, found := d.data[key]; found {
// 			return Response{Success: true, Value: val, Key: key}
// 		}
// 		return Response{Success: false, Message: fmt.Sprintf("Key '%s' not found.", key)}

// 	case "DELETE", "REMOVE":
// 		d.mu.Lock()
// 		defer d.mu.Unlock()
// 		if key == "" {
// 			return Response{Success: false, Message: "Key cannot be empty for DELETE/REMOVE."}
// 		}
// 		if _, found := d.data[key]; found {
// 			delete(d.data, key)
// 			return Response{Success: true, Message: fmt.Sprintf("Key '%s' deleted successfully.", key), Key: key}
// 		}
// 		return Response{Success: false, Message: fmt.Sprintf("Key '%s' not found, nothing deleted.", key)}

// 	case "UPDATE":
// 		d.mu.Lock()
// 		defer d.mu.Unlock()
// 		if key == "" {
// 			return Response{Success: false, Message: "Key cannot be empty for UPDATE."}
// 		}
// 		if _, found := d.data[key]; found {
// 			d.data[key] = req.Value
// 			return Response{Success: true, Message: fmt.Sprintf("Key '%s' updated successfully.", key), Key: key, Value: req.Value}
// 		}
// 		return Response{Success: false, Message: fmt.Sprintf("Key '%s' not found, cannot update.", key)}

// 	case "DUMP":
// 		d.mu.RLock()
// 		defer d.mu.RUnlock()
// 		dumpData := make(map[string]interface{})
// 		for k, v := range d.data {
// 			dumpData[k] = v
// 		}
// 		return Response{Success: true, Message: fmt.Sprintf("Dumped %d keys.", len(d.data)), Data: dumpData}

// 	case "DUMPK", "DUMPKEY":
// 		d.mu.RLock()
// 		defer d.mu.RUnlock()
// 		keys := make([]string, 0, len(d.data))
// 		for k := range d.data {
// 			keys = append(keys, k)
// 		}
// 		return Response{Success: true, Message: fmt.Sprintf("Dumped %d keys.", len(keys)), Data: keys}

// 	case "SEARCH", "SEARCHKEY", "SEARCHKEYVALUE":
// 		d.mu.RLock()
// 		defer d.mu.RUnlock()
// 		search := strings.ToLower(req.Search)
// 		results := make(map[string]interface{})
		
// 		if search == "" {
// 			return Response{Success: false, Message: "Search term cannot be empty."}
// 		}

// 		for k, v := range d.data {
// 			// Check if the top-level key matches
// 			if strings.Contains(strings.ToLower(k), search) {
// 				results[k] = v
// 				continue
// 			}
			
// 			// Perform recursive search on the value (nested key/value search)
// 			if recursiveSearch(v, search) {
// 				results[k] = v
// 				continue
// 			}
// 		}
// 		return Response{Success: true, Message: fmt.Sprintf("Found %d matches for search term '%s' (including nested values).", len(results), req.Search), Data: results}

// 	case "SAVE":
// 		filename := req.Key
// 		if filename == "" {
// 			filename = "dictionary_manual_dump.json" // Manual SAVE defaults to unencrypted JSON
// 		}

// 		// The client SAVE command uses the original unencrypted SaveToFile
// 		if err := d.SaveToFile(filename); err != nil {
// 			return Response{Success: false, Message: fmt.Sprintf("Failed to save to file: %v", err)}
// 		}
// 		return Response{Success: true, Message: fmt.Sprintf("Dictionary saved to '%s'.", filename)}

// 	default:
// 		return Response{Success: false, Message: fmt.Sprintf("Unknown command: %s", req.Command)}
// 	}
// }

// // --- 3. Minimalist WebSocket Implementation ---

// // readFrame reads a single frame (Text or Control) from the connection.
// // Returns payload, opcode, and error.
// func readFrame(conn net.Conn) ([]byte, byte, error) {
// 	reader := bufio.NewReader(conn)
// 	header := make([]byte, 2)
// 	if _, err := io.ReadFull(reader, header); err != nil {
// 		return nil, 0, fmt.Errorf("failed to read frame header: %w", err)
// 	}

// 	fin := (header[0] & 0x80) != 0
// 	opcode := header[0] & 0x0F

// 	if !fin && opcode == opText {
// 		return nil, 0, fmt.Errorf("unsupported fragmented frame")
// 	}

// 	mask := (header[1] & 0x80) != 0
// 	payloadLen := int(header[1] & 0x7F)

// 	var extendedLen uint64
// 	if payloadLen == 126 {
// 		lenBytes := make([]byte, 2)
// 		if _, err := io.ReadFull(reader, lenBytes); err != nil {
// 			return nil, 0, fmt.Errorf("failed to read extended 16-bit length: %w", err)
// 		}
// 		extendedLen = uint64(binary.BigEndian.Uint16(lenBytes))
// 	} else if payloadLen == 127 {
// 		lenBytes := make([]byte, 8)
// 		if _, err := io.ReadFull(reader, lenBytes); err != nil {
// 			return nil, 0, fmt.Errorf("failed to read extended 64-bit length: %w", err)
// 		}
// 		extendedLen = binary.BigEndian.Uint64(lenBytes)
// 	} else {
// 		extendedLen = uint64(payloadLen)
// 	}

// 	if extendedLen > 1024*1024 { // Sanity limit: 1MB
// 		return nil, 0, fmt.Errorf("payload too large (%d bytes)", extendedLen)
// 	}

// 	var maskKey [4]byte
// 	if mask {
// 		if _, err := io.ReadFull(reader, maskKey[:]); err != nil {
// 			return nil, 0, fmt.Errorf("failed to read masking key: %w", err)
// 		}
// 	}

// 	payload := make([]byte, extendedLen)
// 	if _, err := io.ReadFull(reader, payload); err != nil {
// 		return nil, 0, fmt.Errorf("failed to read payload: %w", err)
// 	}

// 	if mask {
// 		for i := uint64(0); i < extendedLen; i++ {
// 			payload[i] ^= maskKey[i%4]
// 		}
// 	}

// 	return payload, opcode, nil
// }

// // writeFrame writes a single frame (Text or Control) to the connection.
// func writeFrame(conn net.Conn, data []byte, opcode byte) error {
// 	payloadLen := len(data)

// 	// 1. Build header (FIN=1, Opcode=provided opcode)
// 	header := []byte{0x80 | opcode}

// 	// 2. Determine length bytes (Mask bit = 0 for server)
// 	if payloadLen <= 125 {
// 		header = append(header, byte(payloadLen))
// 	} else if payloadLen <= 65535 {
// 		header = append(header, 126)
// 		lenBytes := make([]byte, 2)
// 		binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen))
// 		header = append(header, lenBytes...)
// 	} else {
// 		header = append(header, 127)
// 		lenBytes := make([]byte, 8)
// 		binary.BigEndian.PutUint64(lenBytes, uint64(payloadLen))
// 		header = append(header, lenBytes...)
// 	}

// 	// 3. Write header and payload
// 	if _, err := conn.Write(header); err != nil {
// 		return fmt.Errorf("failed to write frame header: %w", err)
// 	}
// 	if _, err := conn.Write(data); err != nil {
// 		return fmt.Errorf("failed to write payload: %w", err)
// 	}

// 	return nil
// }

// // handleConnection performs the WebSocket handshake and processes commands.
// func handleConnection(conn net.Conn, dict *Dictionary) {
// 	defer conn.Close()
// 	log.Printf("Client connected from %s", conn.RemoteAddr())

// 	// --- WebSocket Handshake (omitted for brevity) ---
// 	reader := bufio.NewReader(conn)
// 	req := make(map[string]string)
// 	var secKey string

// 	line, err := reader.ReadString('\n')
// 	if err != nil {
// 		log.Printf("Error reading request line: %v", err)
// 		return
// 	}
// 	if !strings.HasPrefix(line, "GET") || !strings.Contains(line, "HTTP/1.1") {
// 		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
// 		return
// 	}

// 	for {
// 		line, err := reader.ReadString('\n')
// 		if err != nil && err != io.EOF {
// 			log.Printf("Error reading header: %v", err)
// 			return
// 		}

// 		line = strings.TrimSpace(line)
// 		if line == "" {
// 			break
// 		}

// 		parts := strings.SplitN(line, ":", 2)
// 		if len(parts) == 2 {
// 			key := strings.ToLower(strings.TrimSpace(parts[0]))
// 			value := strings.TrimSpace(parts[1])
// 			req[key] = value

// 			if key == "sec-websocket-key" {
// 				secKey = value
// 			}
// 		}

// 		if err == io.EOF {
// 			break
// 		}
// 	}

// 	if req["upgrade"] != "websocket" || req["connection"] != "Upgrade" || secKey == "" {
// 		conn.Write([]byte("HTTP/1.1 400 Bad Request (Missing Upgrade/Connection/Key)\r\n\r\n"))
// 		return
// 	}

// 	h := sha1.New()
// 	h.Write([]byte(secKey + websocketGUID))
// 	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

// 	response := "HTTP/1.1 101 Switching Protocols\r\n" +
// 		"Upgrade: websocket\r\n" +
// 		"Connection: Upgrade\r\n" +
// 		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

// 	if _, err := conn.Write([]byte(response)); err != nil {
// 		log.Printf("Failed to send handshake: %v", err)
// 		return
// 	}

// 	log.Printf("WebSocket Handshake successful with %s", conn.RemoteAddr())

// 	// --- Command Loop (WebSocket Mode) ---
// 	for {
// 		payload, opcode, err := readFrame(conn)
// 		if err != nil {
// 			if err == io.EOF {
// 				log.Printf("Client %s closed connection gracefully.", conn.RemoteAddr())
// 			} else {
// 				log.Printf("Error reading WebSocket frame from %s: %v", conn.RemoteAddr(), err)
// 			}
// 			return
// 		}

// 		switch opcode {
// 		case opText:
// 			// 1. Decode Request
// 			var req Request
// 			if err := json.Unmarshal(payload, &req); err != nil {
// 				resp := Response{Success: false, Message: fmt.Sprintf("Invalid JSON request: %v", err)}
// 				jsonResp, _ := json.Marshal(resp)
// 				writeFrame(conn, jsonResp, opText)
// 				continue
// 			}

// 			// 2. Execute Command
// 			resp := dict.executeCommand(req)

// 			// 3. Encode Response and Send
// 			jsonResp, err := json.Marshal(resp)
// 			if err != nil {
// 				log.Printf("Error marshalling response: %v", err)
// 				jsonResp = []byte(`{"success":false,"message":"Server encoding error."}`)
// 			}

// 			if err := writeFrame(conn, jsonResp, opText); err != nil {
// 				log.Printf("Error writing WebSocket frame to %s: %v", conn.RemoteAddr(), err)
// 				return
// 			}

// 		case opClose:
// 			// Client closed connection explicitly
// 			log.Printf("Client %s sent Close frame.", conn.RemoteAddr())
// 			return

// 		default:
// 			log.Printf("Received unhandled opcode %d from %s, ignoring.", opcode, conn.RemoteAddr())
// 			// Ignore other opcodes (like Ping/Pong)
// 		}
// 	}
// }

// // --- 4. Server Execution ---

// // runServer now accepts two explicit loader files: one for JSON and one for XJSON.
// func runServer(addr string, jsonFile string, xjsonFile string) {
// 	log.Printf("Starting Dictionary Server on ws://%s", addr)

// 	listener, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		log.Fatalf("Failed to listen on %s: %v", addr, err)
// 	}

// 	dict := NewDictionary()

// 	// --- 1. Load Data Priority ---

// 	// A. Load from user-specified JSON file (-l)
// 	if jsonFile != "" {
// 		log.Printf("Attempting to load data from specified JSON file: %s", jsonFile)
// 		dict.LoadFromFile(jsonFile)
// 	}

// 	// B. Load from user-specified XJSON file (-lx) (merges with any existing data)
// 	if xjsonFile != "" {
// 		log.Printf("Attempting to load data from specified XJSON file: %s", xjsonFile)
// 		dict.LoadFromFile(xjsonFile)
// 	}

// 	// C. Fallback: Load from persistence file (which is always .xjson now) if the dictionary is still empty
// 	dict.mu.RLock()
// 	if len(dict.data) == 0 {
// 		dict.mu.RUnlock()
// 		log.Printf("No data loaded from specified files. Checking persistence file: '%s'", persistenceFile)
// 		dict.LoadFromFile(persistenceFile)
// 	} else {
// 		dict.mu.RUnlock()
// 	}

// 	// D. Populate default data ONLY if still empty
// 	dict.mu.RLock()
// 	if len(dict.data) == 0 {
// 		dict.mu.RUnlock()
// 		log.Println("Dictionary is empty after all load attempts. Populating initial default data.")
// 		dict.executeCommand(Request{Command: "SET", Key: "greeting", Value: "hello world"})
// 		dict.executeCommand(Request{Command: "SET", Key: "version", Value: 1.0})
// 		dict.executeCommand(Request{Command: "SET", Key: "list_test", Value: []int{10, 20, 30}})
// 	} else {
// 		dict.mu.RUnlock()
// 	}

// 	// --- 2. Signal Handling for Graceful Shutdown (Crash/Dump Persistence) ---
// 	sig := make(chan os.Signal, 1)
// 	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM) // Catch Ctrl+C and termination signals

// 	go func() {
// 		<-sig // Block until a signal is received
// 		log.Println("Received termination signal. Attempting graceful shutdown...")
// 		// Close the listener, which stops the Accept loop and ensures defer runs.
// 		listener.Close()
// 	}()

// 	// 3. Dump data to encrypted XJSON file on process exit/graceful closure (defer)
// 	defer func() {
// 		log.Printf("Server shutting down. Attempting final state save to %s...", persistenceFile)
// 		// *** IMPORTANT: Use SaveToXJSON for crash/persistence save ***
// 		if err := dict.SaveToXJSON(persistenceFile); err != nil {
// 			log.Printf("CRITICAL SAVE ERROR: %v", err)
// 		}
// 	}()
// 	// --- End Signal Handling ---

// 	for {
// 		conn, err := listener.Accept()
// 		if err != nil {
// 			if strings.Contains(err.Error(), "use of closed network connection") {
// 				log.Println("Listener closed. Exiting server loop.")
// 				return // Exit the runServer function
// 			}
// 			log.Printf("Error accepting connection: %v", err)
// 			continue
// 		}
// 		go handleConnection(conn, dict)
// 	}
// }

// // --- 5. Shell Client ---

// // runShell connects to the server and runs a REPL.
// func runShell(addr string) {
// 	log.Printf("Connecting to Dictionary Server at %s...", addr)

// 	conn, err := net.Dial("tcp", addr)
// 	if err != nil {
// 		log.Fatalf("Failed to connect: %v", err)
// 	}
// 	defer conn.Close()

// 	// --- 1. Perform WebSocket Handshake ---
// 	keyBytes := make([]byte, 16)
// 	for i := 0; i < 16; i++ {
// 		keyBytes[i] = byte(time.Now().UnixNano()>>(i*2)%256)
// 	}
// 	secKey := base64.StdEncoding.EncodeToString(keyBytes)

// 	request := "GET / HTTP/1.1\r\n" +
// 		"Host: " + addr + "\r\n" +
// 		"Upgrade: websocket\r\n" +
// 		"Connection: Upgrade\r\n" +
// 		"Sec-WebSocket-Key: " + secKey + "\r\n" +
// 		"Sec-WebSocket-Version: 13\r\n\r\n"

// 	if _, err := conn.Write([]byte(request)); err != nil {
// 		log.Fatalf("Failed to send handshake request: %v", err)
// 	}

// 	reader := bufio.NewReader(conn)
// 	line, err := reader.ReadString('\n')
// 	if err != nil {
// 		log.Fatalf("Failed to read handshake response line: %v", err)
// 	}

// 	if !strings.Contains(line, "101 Switching Protocols") {
// 		log.Fatalf("Handshake failed. Unexpected response: %s", strings.TrimSpace(line))
// 	}

// 	for {
// 		headerLine, err := reader.ReadString('\n')
// 		if err != nil && err != io.EOF {
// 			log.Fatalf("Error reading handshake headers: %v", err)
// 		}
// 		if strings.TrimSpace(headerLine) == "" {
// 			break
// 		}
// 		if err == io.EOF {
// 			break
// 		}
// 	}

// 	log.Println("WebSocket Handshake successful.")
// 	// --- End Handshake ---

// 	fmt.Println("Connection established. Type 'HELP' for commands or 'QUIT' to exit.")
// 	scanner := bufio.NewScanner(os.Stdin)

// 	for {
// 		fmt.Printf("kv:%s> ", addr)
// 		if !scanner.Scan() {
// 			break
// 		}

// 		input := strings.TrimSpace(scanner.Text())
// 		if input == "" {
// 			continue
// 		}

// 		parts := strings.Fields(input)
// 		command := parts[0]
// 		args := parts[1:]

// 		if strings.ToUpper(command) == "QUIT" || strings.ToUpper(command) == "EXIT" {
// 			fmt.Println("Disconnecting...")
// 			break
// 		}

// 		if strings.ToUpper(command) == "HELP" {
// 			fmt.Println("Available commands (case-insensitive):")
// 			fmt.Println("  SET <key> <value>            : Store a string or JSON value.")
// 			fmt.Println("  GET <key>                  : Retrieve a value.")
// 			fmt.Println("  DELETE <key>               : Remove a key.")
// 			fmt.Println("  UPDATE <key> <new_value>   : Update an existing key.")
// 			fmt.Println("  DUMP                       : Dump all keys and values.")
// 			fmt.Println("  DUMPK                      : Dump all keys only.")
// 			fmt.Println("  SEARCH <term>              : Search keys AND nested JSON values for a term.")
// 			fmt.Println("  SAVE [filename]            : Dumps the dictionary to a specified JSON file on the server.")
// 			fmt.Println("  QUIT/EXIT                  : Close the connection.")
// 			continue
// 		}

// 		req := Request{Command: command}
// 		valueStr := ""

// 		switch strings.ToUpper(command) {
// 		case "SET", "UPDATE":
// 			if len(args) < 2 {
// 				fmt.Println("Error: SET/UPDATE requires a key and a value.")
// 				continue
// 			}
// 			req.Key = args[0]
// 			valueStr = strings.Join(args[1:], " ")
// 			var val interface{}
// 			// Try to unmarshal as JSON first, otherwise treat as raw string
// 			err := json.Unmarshal([]byte(valueStr), &val)
// 			if err != nil {
// 				val = valueStr
// 			}
// 			req.Value = val

// 		case "GET", "READ", "DELETE", "REMOVE":
// 			if len(args) < 1 {
// 				fmt.Printf("Error: %s requires a key.\n", command)
// 				continue
// 			}
// 			req.Key = args[0]

// 		case "SEARCH", "SEARCHKEY", "SEARCHKEYVALUE":
// 			if len(args) < 1 {
// 				fmt.Println("Error: SEARCH requires a search term.")
// 				continue
// 			}
// 			req.Search = strings.Join(args, " ")

// 		case "DUMP", "DUMPK", "DUMPKEY":
// 			// No arguments needed

// 		case "SAVE":
// 			if len(args) > 1 {
// 				fmt.Println("Error: SAVE takes at most one argument (the filename).")
// 				continue
// 			}
// 			if len(args) == 1 {
// 				req.Key = args[0]
// 			}

// 		default:
// 			fmt.Printf("Error: Unknown command '%s'. Type HELP.\n", command)
// 			continue
// 		}

// 		// 1. Marshal Request to JSON
// 		jsonReq, err := json.Marshal(req)
// 		if err != nil {
// 			fmt.Printf("Error preparing request: %v\n", err)
// 			continue
// 		}

// 		// 2. Write WebSocket Frame
// 		if err := writeClientFrame(conn, jsonReq, opText); err != nil {
// 			fmt.Printf("Error sending command: %v\n", err)
// 			return
// 		}

// 		// 3. Read WebSocket Frame Response (Loop only looks for opText or opClose)
// 		var payload []byte
// 		var opcode byte

// 		for {
// 			payload, opcode, err = readFrame(conn)
// 			if err != nil {
// 				if err == io.EOF {
// 					fmt.Println("Connection closed by server.")
// 				} else {
// 					fmt.Printf("Error reading response: %v\n", err)
// 				}
// 				return
// 			}

// 			if opcode == opText {
// 				break // Found the expected TEXT response
// 			}

// 			if opcode == opClose {
// 				fmt.Println("Server closed connection gracefully.")
// 				return
// 			}

// 			// For all other opcodes (control frames), continue waiting for TEXT
// 			log.Printf("Shell ignored unexpected opcode %d from server.", opcode)
// 		}

// 		// 4. Decode Response and print (Payload now contains the TEXT response)
// 		var resp Response
// 		if err := json.Unmarshal(payload, &resp); err != nil {
// 			fmt.Printf("Error parsing server response: %v\nResponse (raw): %s\n", err, string(payload))
// 			continue
// 		}
// 		printResponse(resp)
// 	}
// }

// // writeClientFrame performs client-side framing (must be masked)
// func writeClientFrame(conn net.Conn, data []byte, opcode byte) error {
// 	payloadLen := len(data)
// 	if payloadLen == 0 && opcode == opText {
// 		return nil
// 	}

// 	// 1. Build header (FIN=1, Opcode=provided opcode) and Mask Bit (must be 1 for client)
// 	header := []byte{0x80 | opcode}

// 	// 2. Determine length bytes
// 	maskBit := byte(0x80) // Set mask bit
// 	if payloadLen <= 125 {
// 		header = append(header, byte(payloadLen)|maskBit)
// 	} else if payloadLen <= 65535 {
// 		header = append(header, 126|maskBit)
// 		lenBytes := make([]byte, 2)
// 		binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen))
// 		header = append(header, lenBytes...)
// 	} else {
// 		header = append(header, 127|maskBit)
// 		lenBytes := make([]byte, 8)
// 		binary.BigEndian.PutUint64(lenBytes, uint64(payloadLen))
// 		header = append(header, lenBytes...)
// 	}

// 	// 3. Generate random masking key
// 	maskKey := []byte{byte(time.Now().UnixNano()), byte(time.Now().UnixNano() >> 8), byte(time.Now().UnixNano() >> 16), byte(time.Now().UnixNano() >> 24)}
// 	header = append(header, maskKey...)

// 	// 4. Mask payload
// 	maskedPayload := make([]byte, payloadLen)
// 	for i := 0; i < payloadLen; i++ {
// 		maskedPayload[i] = data[i] ^ maskKey[i%4]
// 	}

// 	// 5. Write header and masked payload
// 	if _, err := conn.Write(header); err != nil {
// 		return fmt.Errorf("failed to write client frame header: %w", err)
// 	}
// 	if _, err := conn.Write(maskedPayload); err != nil {
// 		return fmt.Errorf("failed to write masked payload: %w", err)
// 	}

// 	return nil
// }

// // pretty prints the server response
// func printResponse(resp Response) {
// 	status := "OK"
// 	if !resp.Success {
// 		status = "ERROR"
// 	}

// 	fmt.Printf("[%s] %s\n", status, resp.Message)

// 	if resp.Key != "" && resp.Value != nil {
// 		jsonVal, err := json.MarshalIndent(resp.Value, "", "  ")
// 		if err != nil {
// 			fmt.Printf("  Key: %s -> %v\n", resp.Key, resp.Value)
// 		} else {
// 			fmt.Printf("  Key: %s\n%s\n", resp.Key, string(jsonVal))
// 		}
// 	} else if resp.Data != nil {
// 		jsonVal, err := json.MarshalIndent(resp.Data, "", "  ")
// 		if err != nil {
// 			fmt.Printf("  Data: %v\n", resp.Data)
// 		} else {
// 			fmt.Printf("%s\n", string(jsonVal))
// 		}
// 	}
// }

// // --- 6. Main Entry Point ---

// func main() {
// 	if len(os.Args) < 3 {
// 		fmt.Println("Usage:")
// 		fmt.Println("  Server mode: go run dict_server_shell.go server <host:port> [-l <json_filename>] [-lx <xjson_filename>]")
// 		fmt.Println("  Shell mode:  go run dict_server_shell.go shell <host:port>")
// 		os.Exit(1)
// 	}

// 	mode := strings.ToLower(os.Args[1])
// 	addr := os.Args[2]

// 	jsonFile := ""
// 	xjsonFile := ""

// 	switch mode {
// 	case "server":
// 		// Parse arguments from index 3 for loader flags
// 		for i := 3; i < len(os.Args); i++ {
// 			switch os.Args[i] {
// 			case "-l": // Load unencrypted JSON
// 				if i+1 < len(os.Args) {
// 					jsonFile = os.Args[i+1]
// 					i++ // Skip the next argument (the filename)
// 				} else {
// 					fmt.Println("Error: -l flag requires a filename argument.")
// 					os.Exit(1)
// 				}
// 			case "-lx": // Load XOR encrypted XJSON
// 				if i+1 < len(os.Args) {
// 					xjsonFile = os.Args[i+1]
// 					i++ // Skip the next argument (the filename)
// 				} else {
// 					fmt.Println("Error: -lx flag requires a filename argument.")
// 					os.Exit(1)
// 				}
// 			default:
// 				fmt.Printf("Error: Unknown argument '%s'. Only -l <filename> and -lx <filename> are supported.\n", os.Args[i])
// 				os.Exit(1)
// 			}
// 		}

// 		runServer(addr, jsonFile, xjsonFile)

// 	case "shell":
// 		runShell(addr)
// 	default:
// 		fmt.Printf("Unknown mode: %s. Must be 'server' or 'shell'.\n", mode)
// 		os.Exit(1)
// 	}
// }