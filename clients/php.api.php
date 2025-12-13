<?php

namespace JsonDb;

/**
 * Class ApiClient
 * * A client for connecting to and communicating with the plain TCP JSON API server.
 * It uses a persistent connection and handles newline-delimited JSON messages.
 */
class ApiClient
{
    private string $host;
    private int $port;
    private $socket = null;
    private string $buffer = '';

    // Configuration
    private const DELIMITER = "\n";
    private const TIMEOUT = 5;

    /**
     * @param string $host The server hostname or IP.
     * @param int $port The plain TCP API port (e.g., 8888).
     * @throws \Exception If the connection fails.
     */
    public function __construct(string $host, int $port)
    {
        $this->host = $host;
        $this->port = $port;
        $this->connect();
    }

    /**
     * Establishes the persistent TCP connection.
     * @throws \Exception
     */
    private function connect(): void
    {
        $address = "tcp://{$this->host}:{$this->port}";
        $errno = 0;
        $errstr = '';

        $this->socket = @stream_socket_client(
            $address, 
            $errno, 
            $errstr, 
            self::TIMEOUT,
            STREAM_CLIENT_CONNECT
        );

        if (!$this->socket) {
            throw new \Exception("Failed to connect to API at {$address}: [{$errno}] {$errstr}");
        }

        // Set non-blocking mode temporarily, but we'll primarily use blocking reads
        stream_set_blocking($this->socket, true);
        stream_set_timeout($this->socket, self::TIMEOUT);
        echo "[INFO] Connected to API gateway at {$this->host}:{$this->port}\n";
    }

    /**
     * Closes the underlying TCP connection when the object is destroyed.
     */
    public function __destruct()
    {
        $this->close();
    }

    /**
     * Explicitly closes the socket connection.
     */
    public function close(): void
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
            $this->socket = null;
            echo "[INFO] Connection closed.\n";
        }
    }

    /**
     * Sends a command and waits for a single, newline-delimited JSON response.
     * @param array $command The command dictionary (Op, Key, Value, etc.).
     * @return array The decoded JSON response.
     * @throws \Exception
     */
    public function executeCommand(array $command): array
    {
        if (!is_resource($this->socket)) {
            throw new \Exception("Client is not connected or connection was closed.");
        }

        // 1. Serialize and Send Request
        $jsonCommand = json_encode($command) . self::DELIMITER;
        $bytesWritten = fwrite($this->socket, $jsonCommand);
        
        if ($bytesWritten === false || $bytesWritten < strlen($jsonCommand)) {
            // Check for socket errors after failure to write
            $meta = stream_get_meta_data($this->socket);
            if ($meta['timed_out']) {
                throw new \Exception("Socket write timed out.");
            }
            throw new \Exception("Failed to write command to socket.");
        }

        // 2. Receive Response
        return $this->recvResponse();
    }

    /**
     * Reads from the socket buffer until a complete response is found.
     * @return array The decoded response.
     * @throws \Exception
     */
    private function recvResponse(): array
    {
        // Keep reading until the delimiter is found in the buffer
        while (strpos($this->buffer, self::DELIMITER) === false) {
            // Read up to 4KB
            $chunk = fread($this->socket, 4096); 
            
            if ($chunk === false) {
                // Check for stream timeout or error
                $meta = stream_get_meta_data($this->socket);
                if ($meta['timed_out']) {
                    throw new \Exception("Socket read timed out.");
                }
                throw new \Exception("Error reading from socket (E_IO).");
            }
            if ($chunk === '') {
                // End of file/connection closed by server
                throw new \Exception("Connection closed by server unexpectedly.");
            }
            $this->buffer .= $chunk;
        }

        // 3. Extract one complete message and update buffer
        [$rawResponse, $this->buffer] = explode(self::DELIMITER, $this->buffer, 2);

        // 4. Decode JSON
        $response = json_decode(trim($rawResponse), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception("Failed to decode JSON response: " . json_last_error_msg() . 
                                 ". Raw: " . substr($rawResponse, 0, 100) . "...");
        }

        return $response;
    }

    // --- Specific API Methods (Wrappers) ---

    public function set(string $key, $value): array
    {
        $cmd = ["Op" => "SET", "Key" => $key, "Value" => $value];
        return $this->executeCommand($cmd);
    }

    public function get(string $key): array
    {
        $cmd = ["Op" => "GET", "Key" => $key];
        return $this->executeCommand($cmd);
    }

    public function delete(string $key): array
    {
        $cmd = ["Op" => "DELETE", "Key" => $key];
        return $this->executeCommand($cmd);
    }

    public function dump(): array
    {
        $cmd = ["Op" => "DUMP"];
        return $this->executeCommand($cmd);
    }

    public function search(string $term): array
    {
        $cmd = ["Op" => "SEARCH", "Term" => $term];
        return $this->executeCommand($cmd);
    }
}

// ---------------------------------------------------------------------
// --- Example Usage ---
// ---------------------------------------------------------------------

function runExamples(string $host, int $port): void
{
    try {
        // 1. Establish connection (automatically done in constructor)
        $client = new ApiClient($host, $port);

        // --- Test 1: SET (key, string value) ---
        $setKey = "server:status";
        $resp = $client->set($setKey, "ACTIVE");
        echo "\n--- SET {$setKey} ---\n";
        if ($resp['status'] === "OK") {
            echo "✅ Success: Key {$setKey} set.\n";
        } else {
            echo "❌ Error: {$resp['status']} - {$resp['message']}\n";
        }

        // --- Test 2: GET (key) ---
        $resp = $client->get($setKey);
        echo "\n--- GET {$setKey} ---\n";
        if ($resp['status'] === "OK") {
            echo "✅ Success: Value: " . print_r($resp['value'], true) . "\n";
        } else {
            echo "❌ Error: {$resp['status']} - {$resp['message']}\n";
        }

        // --- Test 3: SET (key, JSON object value) ---
        $jsonValue = ['latency_ms' => 12.5, 'health' => 'GREEN'];
        $jsonKey = "metrics:api";
        $resp = $client->set($jsonKey, $jsonValue);
        echo "\n--- SET {$jsonKey} ---\n";
        if ($resp['status'] === "OK") {
            echo "✅ Success: JSON object set.\n";
        } else {
            echo "❌ Error: {$resp['status']} - {$resp['message']}\n";
        }

        // --- Test 4: SEARCH (term) ---
        $searchTerm = "GREEN";
        $resp = $client->search($searchTerm);
        echo "\n--- SEARCH \"{$searchTerm}\" ---\n";
        if ($resp['status'] === "OK") {
            echo "✅ Success: Results found:\n";
            echo json_encode($resp['results'], JSON_PRETTY_PRINT) . "\n";
        } else {
            echo "❌ Error: {$resp['status']} - {$resp['message']}\n";
        }

        // --- Test 5: DUMP all data ---
        $resp = $client->dump();
        echo "\n--- DUMP ---\n";
        if ($resp['status'] === "OK") {
            echo "Store Contents:\n";
            echo json_encode($resp['data'], JSON_PRETTY_PRINT) . "\n";
        } else {
            echo "❌ Error: {$resp['status']} - {$resp['message']}\n";
        }

    } catch (\Exception $e) {
        echo "\n[FATAL ERROR] " . $e->getMessage() . "\n";
    }
}

// --- Execution ---
runExamples(API_HOST, API_PORT);