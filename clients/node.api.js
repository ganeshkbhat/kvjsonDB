const tls = require('tls');
const fs = require('fs');

/**
 * Custom Error for the DB Client
 */
class ClientError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'ClientError';
        this.code = code;
    }
}

/**
 * JsonDbClient: Connects to and executes commands on the TCP Server using mTLS.
 */
class JsonDbClient {
    /**
     * @param {object} config - Configuration object
     * @param {string} config.host - Server host (e.g., 'localhost')
     * @param {number} config.port - Server port (e.g., 9999)
     * @param {string} config.clientCertPath - Path to client's public certificate
     * @param {string} config.clientKeyPath - Path to client's private key
     * @param {string} config.caCertPath - Path to the Root CA certificate
     */
    constructor(config) {
        this.config = config;
        this.socket = null;
        this.isAuthenticated = false;
        this.dataBuffer = ''; 
        this.responseQueue = []; 
        this.timeout = 5000; // 5 seconds connection timeout
    }

    /**
     * Establishes the mTLS connection to the server.
     * @returns {Promise<void>}
     */
    connect() {
        return new Promise((resolve, reject) => {
            if (this.socket) {
                this.socket.destroy();
            }

            console.log(`[LOG] Attempting mTLS connection to ${this.config.host}:${this.config.port}`);
            
            try {
                const options = {
                    host: this.config.host,
                    port: this.config.port,
                    key: fs.readFileSync(this.config.clientKeyPath),
                    cert: fs.readFileSync(this.config.clientCertPath),
                    ca: fs.readFileSync(this.config.caCertPath),
                    requestCert: true, 
                    rejectUnauthorized: true,
                };

                this.socket = tls.connect(options, () => {
                    if (!this.socket.authorized) {
                        console.error(`[ERROR] mTLS Handshake FAILED: Client certificate not authorized by CA.`);
                        console.error(`[ERROR] Authorization Error Details: ${this.socket.authorizationError}`);
                        this.socket.destroy();
                        return reject(new ClientError(`mTLS Authorization Failed: ${this.socket.authorizationError}`, 'AUTH_FAILED'));
                    }

                    console.log(`[LOG] Connected securely to ${this.config.host}:${this.config.port}`);
                    const cert = this.socket.getCertificate();
                    if (cert && cert.subject) {
                        console.log(`[LOG] mTLS Handshake successful. Client CN: ${cert.subject.CN}`);
                    }
                    resolve();
                });
                
            } catch (fsError) {
                return reject(new ClientError(`File System Error reading credentials: ${fsError.message}`, 'FILE_ERROR'));
            }

            this.socket.setEncoding('utf8');

            // Connection Timeout
            this.socket.setTimeout(this.timeout, () => {
                const timeoutError = new ClientError(`Connection timed out after ${this.timeout}ms. Check server status/firewall.`, 'CONNECT_TIMEOUT');
                this._clearQueue(timeoutError);
                this.socket.destroy(timeoutError);
            });

            this.socket.on('data', (data) => this._handleData(data));
            
            this.socket.on('error', (err) => {
                console.error(`[ERROR] Socket-level Error received: ${err.message}`);
                this._clearQueue(err);
                reject(new ClientError(`Connection Error: ${err.message}`, 'SOCKET_ERROR'));
            });

            this.socket.on('close', (hadError) => {
                const closeMsg = hadError ? 'with error' : 'cleanly';
                console.log(`[LOG] Connection closed ${closeMsg}.`);
                const closeError = new ClientError('Connection closed by server.', 'CONNECTION_CLOSED');
                this._clearQueue(closeError);
                this.isAuthenticated = false;
                this.socket = null;
            });
        });
    }

    /**
     * Sends a command to the server by first formatting it into the required JSON request:
     * { "command": "COMMAND_NAME", "args": [arg1, arg2, ...] }
     * @param {string} commandName - The name of the command (e.g., "LOGIN")
     * @param {Array<any>} args - Arguments for the command.
     * @returns {Promise<any>} - Resolves with parsed server response.
     */
    _sendCommand(commandName, args) {
        if (!this.socket) {
            return Promise.reject(new ClientError('Not connected to the server.', 'NOT_CONNECTED'));
        }

        return new Promise((resolve, reject) => {
            // 1. Structure the command into the JSON request format
            const requestObject = {
                command: commandName,
                args: args
            };
            
            // 2. Stringify the request and append the newline delimiter
            const jsonMessage = JSON.stringify(requestObject);
            const message = `${jsonMessage}\n`;

            // 3. Queue the promise for the response
            this.responseQueue.push({ resolve, reject, command: commandName });
            
            this.socket.write(message, (err) => {
                if (err) {
                    this.responseQueue.pop(); 
                    reject(new ClientError(`Write failed: ${err.message}`, 'WRITE_ERROR'));
                }
            });
        });
    }

    /**
     * Handles incoming data, parses complete messages, and resolves waiting promises.
     * Modified to correctly handle unsolicited "INFO" messages.
     */
    _handleData(data) {
        this.dataBuffer += data;
        
        let newlineIndex;
        while ((newlineIndex = this.dataBuffer.indexOf('\n')) !== -1) {
            const rawMessage = this.dataBuffer.substring(0, newlineIndex).trim();
            this.dataBuffer = this.dataBuffer.substring(newlineIndex + 1);

            if (!rawMessage) continue;

            try {
                const jsonResponse = JSON.parse(rawMessage);
                
                // --- CRITICAL CHANGE: Handle INFO status separately ---
                if (jsonResponse.status === 'INFO') {
                    // Log the INFO message and ignore it, do not touch the responseQueue
                    console.log(`[SERVER INFO] ${jsonResponse.message || 'No message provided.'}`);
                    continue; // Skip the rest of the processing and look for the next message
                }
                // --- END CRITICAL CHANGE ---

                // If it's not INFO, it MUST be a response to a command
                if (this.responseQueue.length === 0) {
                     console.warn(`[WARNING] Received unexpected response with status "${jsonResponse.status}". Raw message: ${rawMessage}`);
                     continue;
                }
                
                const responseHandler = this.responseQueue.shift();

                // 2. Validate JSON structure (must have 'status' for commands)
                if (jsonResponse.status) {
                    if (jsonResponse.status === 'OK') {
                        if (responseHandler.command === 'LOGIN') {
                            this.isAuthenticated = true;
                        }
                        responseHandler.resolve(jsonResponse.data);
                    } else if (jsonResponse.status === 'ERROR') {
                        responseHandler.reject(new ClientError(jsonResponse.message || 'Unknown Server Error', 'SERVER_ERROR'));
                    } else {
                        // 2b. Unknown status value that is not INFO
                        console.error(`[DIAGNOSTIC] Server sent unknown status: "${jsonResponse.status}". Raw message: ${rawMessage}`);
                        responseHandler.reject(new ClientError('Invalid server response status value.', 'INVALID_STATUS'));
                    }
                } else {
                    // This case is unlikely now that we handle INFO and expect structure
                    console.error(`[DIAGNOSTIC] Server response missing 'status' field. Raw message: ${rawMessage}`);
                    responseHandler.reject(new ClientError('Invalid server response format (Missing Status).', 'INVALID_RESPONSE_FORMAT'));
                }

            } catch (e) {
                // Failed to parse as JSON (This should now only happen if the server sends bad data)
                console.error(`[DIAGNOSTIC] Failed to parse as JSON. Raw message received: "${rawMessage}". Error: ${e.message}`);
                // Since this error occurred *before* the LOGIN command was processed, we need to reject the promise for LOGIN.
                if (this.responseQueue.length > 0) {
                    const nextHandler = this.responseQueue.shift();
                    nextHandler.reject(new ClientError(`Protocol error. Server sent unparseable data: "${rawMessage}".`, 'PROTOCOL_ERROR'));
                }
            }
        }
    }
    
    /** Clears all pending responses with an error. */
    _clearQueue(error) {
        while(this.responseQueue.length > 0) {
            this.responseQueue.shift().reject(error);
        }
    }

    // --- API Methods: Mapping to Server Commands ---

    // 🔐 Authentication & Authorization
    async login(userId, password) {
        return this._sendCommand('LOGIN', [userId, password]);
    }

    async logout() {
        return this._sendCommand('LOGOUT', []);
    }

    // 📦 Key-Value Data Store Commands
    async set(key, value) {
        const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);
        return this._sendCommand('SET', [key, valueStr]);
    }
    
    async get(key) {
        return this._sendCommand('GET', [key]);
    }

    async delete(key) {
        return this._sendCommand('DELETE', [key]);
    }

    async putBlob(key, localFilePath) {
        return this._sendCommand('PUTBLOB', [key, localFilePath]);
    }
    
    async getBlob(key) {
        return this._sendCommand('GETBLOB', [key]);
    }
    
    async deleteBlob(key) {
        return this._sendCommand('DELETEBLOB', [key]);
    }


    // 👤 User & Group Management (Admin Required)
    async createUser(id, password) {
        return this._sendCommand('CREATEUSER', [id, password]);
    }
    
    async deleteUser(id) {
        return this._sendCommand('DELETEUSER', [id]);
    }
    
    async viewUser(id = '') { 
        return this._sendCommand('VIEWUSER', [id]);
    }

    async changePassword(id, newPassword) {
        return this._sendCommand('CHANGEPASSWORD', [id, newPassword]);
    }
    
    async updateUserGroups(id, groupsArray) {
        const groupsList = groupsArray.join(',');
        return this._sendCommand('UPDATEUSER', [id, '-groups', groupsList]); 
    }

    async createGroup(name) {
        return this._sendCommand('CREATEGROUP', [name]);
    }
    
    async deleteGroup(name) {
        return this._sendCommand('DELETEGROUP', [name]);
    }
    
    async viewGroup(name = '') { 
        return this._sendCommand('VIEWGROUP', [name]);
    }

    async updateGroupMembers(groupName, membersArray) {
        const membersList = membersArray.join(',');
        return this._sendCommand('UPDATEGROUP', [groupName, '-members', membersList]);
    }

    async addUserToGroup(userId, groupName) {
        return this._sendCommand('ADDUSERTOGROUP', [userId, groupName]);
    }
    
    async removeUserFromGroup(userId, groupName) {
        return this._sendCommand('REMOVEUSERFROMGROUP', [userId, groupName]);
    }

    // 🔒 Access Control List (ACL) Management (Admin Required)
    async setPermission(key, entityType, id, permission) {
        return this._sendCommand('SETPERM', [key, entityType, id, permission]);
    }
    
    async removePermission(key, entityType, id) {
        return this._sendCommand('REMOVEPERM', [key, entityType, id]);
    }
    
    async updateACL(key, defaultPerm) {
        return this._sendCommand('UPDATEACL', [key, defaultPerm]);
    }

    async viewACL(key = '') { 
        return this._sendCommand('VIEWACL', [key]);
    }
    
    async deleteACL(key) {
        return this._sendCommand('DELETEACL', [key]);
    }


    // 🔎 Search & Bulk Delete (Requires Token)
    async search(string) {
        return this._sendCommand('SEARCH', [string]);
    }

    async searchKey(substring) {
        return this._sendCommand('SEARCHKEY', [substring]);
    }

    async deleteKey(substring) {
        return this._sendCommand('DELETEKEY', [substring]);
    }

    // ⚙️ System & Connection Commands (Server-side execution)
    async dump(filename = '') {
        return this._sendCommand('DUMP', [filename]);
    }
    
    async load(filename) {
        return this._sendCommand('LOAD', [filename]);
    }

    // --- Connection Utilities (Local) ---

    isConnected() {
        return !!this.socket;
    }

    disconnect() {
        if (this.socket) {
            this.socket.end();
            this.socket = null;
        }
    }
}

module.exports = JsonDbClient;