import socket
import json
import logging
import sys

# --- Configuration (Matches server defaults) ---
API_HOST = 'localhost'
API_PORT = 8888
# Server uses newline (\n) as the message delimiter
DELIMITER = b'\n'

# Set up logging for better error reporting
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class APIClient:
    """
    A persistent client for the plain TCP JSON API server.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self._buffer = b''
        self.connect()

    def connect(self):
        """Establishes a single, persistent TCP connection."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)  # Set a timeout for connect/recv
            self.sock.connect((self.host, self.port))
            logging.info(f"Connected to API gateway at {self.host}:{self.port}")
            # 
        except Exception as e:
            logging.error(f"Failed to connect to API at {self.host}:{self.port}: {e}")
            sys.exit(1)

    def close(self):
        """Closes the underlying TCP connection."""
        if self.sock:
            self.sock.close()
            logging.info("Connection closed.")

    def _recv_response(self):
        """
        Receives data from the socket until a complete, newline-delimited 
        JSON message is found in the buffer.
        """
        # 1. Read until delimiter is found
        while DELIMITER not in self._buffer:
            try:
                # Read up to 4KB of data
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Connection reset by peer.")
                self._buffer += chunk
            except socket.timeout:
                raise TimeoutError("Socket receive timed out.")
            except Exception as e:
                raise ConnectionError(f"Error reading from socket: {e}")

        # 2. Extract one complete message
        response_bytes, self._buffer = self._buffer.split(DELIMITER, 1)

        # 3. Decode and Deserialize
        try:
            raw_response = response_bytes.decode('utf-8')
            response = json.loads(raw_response)
            return response
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON response. Raw: {raw_response[:100]}...")
            raise json.JSONDecodeError(f"Error unmarshalling response: {e}", raw_response, e.pos)

    def execute_command(self, command):
        """Sends a Command dictionary and returns the Response dictionary."""
        if not self.sock:
            raise ConnectionError("Client is not connected.")
            
        # 1. Serialize and Send Request
        try:
            json_command = json.dumps(command).encode('utf-8')
            self.sock.sendall(json_command + DELIMITER)
        except Exception as e:
            raise ConnectionError(f"Error sending command: {e}")

        # 2. Receive Response
        return self._recv_response()

    # --- Specific API Methods (Wrappers) ---

    def set(self, key, value):
        """Sends a SET command."""
        cmd = {"Op": "SET", "Key": key, "Value": value}
        return self.execute_command(cmd)

    def get(self, key):
        """Sends a GET command."""
        cmd = {"Op": "GET", "Key": key}
        return self.execute_command(cmd)

    def delete(self, key):
        """Sends a DELETE command."""
        cmd = {"Op": "DELETE", "Key": key}
        return self.execute_command(cmd)

    def dump(self):
        """Sends a DUMP command."""
        cmd = {"Op": "DUMP"}
        return self.execute_command(cmd)
    
    def search(self, term):
        """Sends a SEARCH command."""
        cmd = {"Op": "SEARCH", "Term": term}
        return self.execute_command(cmd)

# ---------------------------------------------------------------------
# --- Example Usage ---
# ---------------------------------------------------------------------

def run_examples():
    """Demonstrates usage of the APIClient."""
    client = None
    try:
        client = APIClient(API_HOST, API_PORT)

        # --- Test 1: SET (key, string value) ---
        set_key = "user:42"
        resp = client.set(set_key, "Alice Smith")
        print(f"\n--- SET {set_key} ---")
        if resp.get("status") == "OK":
            print(f"✅ Success: Key {set_key} set.")
        else:
            print(f"❌ Error: {resp.get('status')} - {resp.get('message')}")

        # --- Test 2: GET (key) ---
        resp = client.get(set_key)
        print(f"\n--- GET {set_key} ---")
        if resp.get("status") == "OK":
            print(f"✅ Success: Value: {resp.get('value')}")
        else:
            print(f"❌ Error: {resp.get('status')} - {resp.get('message')}")
            
        # --- Test 3: SET (key, JSON object value) ---
        json_value = {"city": "London", "level": "admin"}
        json_key = "profile:42"
        resp = client.set(json_key, json_value)
        print(f"\n--- SET {json_key} ---")
        if resp.get("status") == "OK":
            print("✅ Success: JSON object set.")
        else:
            print(f"❌ Error: {resp.get('status')} - {resp.get('message')}")
        
        # --- Test 4: SEARCH (term) ---
        search_term = "admin"
        resp = client.search(search_term)
        print(f"\n--- SEARCH \"{search_term}\" ---")
        if resp.get("status") == "OK":
            print("✅ Success: Results found:")
            print(json.dumps(resp.get('results'), indent=2))
        else:
            print(f"❌ Error: {resp.get('status')} - {resp.get('message')}")

        # --- Test 5: DUMP all data ---
        resp = client.dump()
        print("\n--- DUMP ---")
        if resp.get("status") == "OK":
            print("Store Contents:")
            print(json.dumps(resp.get('data'), indent=2))
        else:
            print(f"❌ Error: {resp.get('status')} - {resp.get('message')}")

    except (ConnectionError, TimeoutError, json.JSONDecodeError) as e:
        logging.error(f"Application Error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    run_examples()