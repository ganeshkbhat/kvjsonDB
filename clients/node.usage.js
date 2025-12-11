const JsonDbClient = require('./node.api'); // Make sure path is correct

// --- Configuration ---
const config = {
    host: 'localhost',
    port: 7000,
    // IMPORTANT: Update these paths to your actual certificate files
    clientCertPath: './client.crt', 
    clientKeyPath: './client.key',
    caCertPath: './ca.crt',
};

async function main() {
    const client = new JsonDbClient(config);

    try {
        // 1. Establish mTLS Connection
        console.log('Attempting to connect to the server...');
        await client.connect();
        
        // 2. Login to get a session token (assuming 'admin_user' exists and has permissions)
        console.log('\n--- Authentication ---');
        const USER_ID = 'admin';
        const PASSWORD = 'password';
        
        const loginResponse = await client.login(USER_ID, PASSWORD);
        console.log(`✅ Login successful! Session token details:`, loginResponse);
        
        // 3. Run Data Commands (Requires READ/WRITE permissions on the key)
        console.log('\n--- Data Operations (SET/GET/DELETE) ---');
        const dataKey = 'config:app:settings';
        const dataValue = { version: 2.1, maintenance_mode: false };
        
        // SET operation
        console.log(`Writing value to key: ${dataKey}`);
        const setResponse = await client.set(dataKey, dataValue);
        console.log('SET Response:', setResponse);

        // GET operation
        console.log(`\nReading value from key: ${dataKey}`);
        const getResponse = await client.get(dataKey);
        // Data returned from server is likely a JSON string, so we parse it here
        const parsedValue = JSON.parse(getResponse);
        console.log('GET Result (Parsed):', parsedValue); 
        
        // 4. Run Security/Admin Commands (Requires ADMIN permission on 'security_db')
        console.log('\n--- Security Operations (Admin Required) ---');
        const newUserId = 'analytics_service';
        
        // CREATEUSER operation
        console.log(`Creating new user: ${newUserId}`);
        const createUserResponse = await client.createUser(newUserId, 'api_token_123');
        console.log('CREATEUSER Response:', createUserResponse);

        // SETPERM operation: Granting READ (1) permission to the new user on the data key
        console.log(`\nGranting READ permission to user ${newUserId} on key ${dataKey}`);
        const setPermResponse = await client.setPermission(dataKey, 'user', newUserId, 1);
        console.log('SETPERM Response:', setPermResponse);
        
        // 5. Cleanup
        console.log('\n--- Cleanup ---');
        
        // DELETE operation
        console.log(`Deleting data key: ${dataKey}`);
        await client.delete(dataKey);

        // DELETEUSER operation
        console.log(`Deleting new user: ${newUserId}`);
        await client.deleteUser(newUserId);
        
    } catch (error) {
        console.error('\n❌ --- A CRITICAL ERROR OCCURRED ---');
        if (error.code) {
            console.error(`[${error.code}] ${error.message}`);
        } else {
            console.error(error);
        }
    } finally {
        // Ensure connection and session are properly closed
        if (client.isAuthenticated) {
             console.log('\nLogging out session...');
             await client.logout().catch(e => console.error('Warning: Logout failed:', e.message));
        }
        if (client.isConnected()) {
             client.disconnect();
             console.log('Client disconnected from socket.');
        }
    }
}

main();

