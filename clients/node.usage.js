const net = require('net');
const { Writable } = require('stream');

// --- Configuration (Matches server defaults) ---
const API_HOST = 'localhost';
const API_PORT = 8888;

// --- API Client Class ---

class APIClient {
    /**
     * @param {string} host 
     * @param {number} port 
     */
    constructor(host, port) {
        this.host = host;
        this.port = port;
        /** @type {net.Socket | null} */
        this.client = null;
        /** @type {Promise<net.Socket>} */
        this.connectionPromise = this.connect();
        /** @type {Function[]} */
        this.commandQueue = [];
        this.isProcessing = false;
        this.buffer = ''; // Buffer for incoming data
    }

    /**
     * Establishes a single, persistent TCP connection.
     * @returns {Promise<net.Socket>}
     */
    connect() {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();
            this.client = client;

            client.connect(this.port, this.host, () => {
                console.log(`[API Client] Connected to ${this.host}:${this.port}`);
                resolve(client);
            });

            // Set up data listener to handle responses
            client.on('data', (data) => {
                this.buffer += data.toString();
                this.processResponses();
            });

            client.on('error', (err) => {
                console.error(`[API Client] Socket Error: ${err.message}`);
                this.disconnect();
                reject(new Error(`Connection failed: ${err.message}`));
            });

            client.on('close', () => {
                console.log('[API Client] Connection closed.');
                this.client = null;
                // Reject any remaining commands in the queue
                this.rejectQueue(new Error("Connection closed unexpectedly."));
            });
        });
    }

    /**
     * Processes the incoming buffer data, looking for JSON responses delimited by newline.
     */
    processResponses() {
        let newlineIndex;
        // Check for complete messages (delimited by \n)
        while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
            const rawResponse = this.buffer.substring(0, newlineIndex);
            this.buffer = this.buffer.substring(newlineIndex + 1);

            // Resolve the oldest waiting command in the queue
            const resolveCommand = this.commandQueue.shift(); 
            if (resolveCommand) {
                try {
                    const response = JSON.parse(rawResponse.trim());
                    resolveCommand.resolve(response);
                } catch (error) {
                    console.error(`[API Client] Failed to parse JSON. Raw: ${rawResponse.trim()}`);
                    resolveCommand.reject(new Error(`Error unmarshalling response: ${error.message}`));
                }
            }
        }
    }
    
    /**
     * Rejects all promises currently waiting in the command queue.
     * @param {Error} error 
     */
    rejectQueue(error) {
        while (this.commandQueue.length > 0) {
            this.commandQueue.shift().reject(error);
        }
    }


    /**
     * Sends a Command object and waits for a Response on the persistent connection.
     * @param {Object} command 
     * @returns {Promise<Object>}
     */
    async executeCommand(command) {
        // Wait for the connection to be established
        await this.connectionPromise;

        return new Promise((resolve, reject) => {
            // 1. Queue the promise callbacks
            this.commandQueue.push({ resolve, reject });

            // 2. Send the request
            try {
                const jsonCommand = JSON.stringify(command);
                // Ensure the client is still available before writing
                if (this.client && !this.client.destroyed) {
                    this.client.write(jsonCommand + '\n');
                } else {
                    reject(new Error("Connection is not active."));
                }
            } catch (error) {
                // If writing fails, remove the command from the queue
                this.commandQueue.pop(); 
                reject(new Error(`Error marshalling/writing command: ${error.message}`));
            }
        });
    }

    /**
     * Closes the persistent TCP connection.
     */
    disconnect() {
        if (this.client) {
            this.client.end();
        }
    }
}

// ---------------------------------------------------------------------
// --- Specific API Methods (Wrappers) ---
// ---------------------------------------------------------------------

/**
 * Creates an API object tied to the client instance.
 * @param {APIClient} client 
 */
const createAPIWrappers = (client) => ({
    /** @param {string} key */
    get: (key) => client.executeCommand({ Op: "GET", Key: key }),
    
    /** @param {string} key @param {*} value */
    set: (key, value) => client.executeCommand({ Op: "SET", Key: key, Value: value }),
    
    /** @param {string} key */
    delete: (key) => client.executeCommand({ Op: "DELETE", Key: key }),
    
    dump: () => client.executeCommand({ Op: "DUMP" }),

    /** @param {string} term */
    search: (term) => client.executeCommand({ Op: "SEARCH", Term: term }),

    /** @param {string} term */
    searchKey: (term) => client.executeCommand({ Op: "SEARCHKEY", Term: term }),

    /** @param {Object} data */
    load: (data) => client.executeCommand({ Op: "LOAD", Data: data }),
});

// ---------------------------------------------------------------------
// --- Example Usage ---
// ---------------------------------------------------------------------

async function runExamples() {
    const client = new APIClient(API_HOST, API_PORT);
    const API = createAPIWrappers(client);
    
    try {
        // Ensure connection is ready before starting tests
        await client.connectionPromise; 

        // --- Test 1: SET (key, string value) ---
        const setKey = "device:abc";
        let resp = await API.set(setKey, "Smart Switch v1");
        console.log(`\n--- SET ${setKey} ---`);
        if (resp.status === "OK") {
            console.log(`✅ Success: Key ${setKey} set.`);
        } else {
            console.log(`❌ Error: ${resp.status} - ${resp.message}`);
        }

        // --- Test 5: DUMP all data ---
        resp = await API.dump();
        console.log(`\n--- DUMP ---`);
        console.log(`\n`, resp);

        // --- Test 2: GET (key) ---
        resp = await API.get(setKey);
        console.log(`\n--- GET ${setKey} ---`);
        if (resp.status === "OK") {
            console.log(`✅ Success: Value: ${resp.value}`);
        } else {
            console.log(`❌ Error: ${resp.status} - ${resp.message}`);
        }

        // --- Test 3: SET (key, JSON object value) ---
        const jsonValue = { location: "kitchen", status: "on", temp: 24.5 };
        const jsonKey = "sensor:temp";
        resp = await API.set(jsonKey, jsonValue);
        console.log(`\n--- SET ${jsonKey} ---`);
        if (resp.status === "OK") {
            console.log("✅ Success: JSON object set.");
        } else {
            console.log(`❌ Error: ${resp.status} - ${resp.message}`);
        }

        // --- Test 4: SEARCH (term) ---
        const searchTerm = "kitchen";
        resp = await API.search(searchTerm);
        console.log(`\n--- SEARCH "${searchTerm}" ---`);
        if (resp.status === "OK") {
            console.log("✅ Success: Results found:");
            console.log(JSON.stringify(resp.results, null, 2));
        } else {
            console.log(`❌ Error: ${resp.status} - ${resp.message}`);
        }

        // --- Test 5: DUMP all data ---
        resp = await API.dump();
        console.log(`\n--- DUMP ---`);
        if (resp.status === "OK") {
            console.log("Store Contents:");
            console.log(JSON.stringify(resp.data, null, 2));
        } else {
            console.log(`❌ Error: ${resp.status} - ${resp.message}`);
        }

    } catch (error) {
        console.error(`\n[FATAL ERROR]`, error.message);
    } finally {
        client.disconnect();
    }
}

runExamples();