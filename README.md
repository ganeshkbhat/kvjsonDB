# kvjsonDB
kvjsonDB - fast, secure and private, memory leak resistant redis like key value json based data store. an attempt to make a simple small datastore


<!-- 

# Specific IP
./jsondb -s=db -h 10.0.0.5 -p 8080
go run jsondb.go -s=db -h 10.0.0.5 -p 8080


# Listen on ALL interfaces (IP: 0.0.0.0)
./jsondb -s=db -h 0.0.0.0 -p 9999
go run jsondb.go  -s=db -h 0.0.0.0 -p 9999

# Run the client shell and connect to the server
./json-db -s shell --cert client.crt --key client.key --ca-cert ca.crt
go run jsondb.go -s shell --cert client.crt --key client.key --ca-cert ca.crt

# Run the server on port 9999 (default)
./json-db -s db --cert server.crt --key server.key --ca-cert ca.crt -l initial_data.json -h 0.0.0.0 -p 9999
go run jsondb.go -s db --cert server.crt --key server.key --ca-cert ca.crt -l store_dump.json -h 0.0.0.0 -p 9999
 

-->


go run main.go -s=db -h=0.0.0.0 -p=8080 -dt=30m -log=app.log -cert=server.crt -key=server.key -ca-cert=ca.crt -l=initial_data.json -dt=1h 


go run main.go -s=shell -cert=client.crt -key=client.key -ca-cert=ca.crt -h=192.168.1.10 -p=8888   


Command,Usage,Description
SET,SET <key> <value/json>,Sets a key-value pair. The value can be a simple string or a valid JSON structure.
GET,GET <key>,Retrieves the value associated with the specified key.
DELETE,DELETE <key>,"Removes the key-value pair. If the key points to a BLOB, the associated file is also deleted."

Command,Usage,Description
PUTBLOB,PUTBLOB <key> <local_file_path>,Uploads the local file to the server's BLOB storage and registers it under <key>.
GETBLOB,GETBLOB <key>,Downloads the BLOB stored under <key>. Saves the file locally as retrieved_<original_name>.
DELETEBLOB,DELETEBLOB <key>,Explicitly deletes the BLOB object and its associated file on the server. Fails if the key is not a BLOB.

Command,Usage,Description
SEARCH,SEARCH <string>,Searches for the <string> within both key names and JSON values.
SEARCHKEY,SEARCHKEY <substring>,Finds all keys that contain the specified <substring>.
DELETEKEY,DELETEKEY <substring>,DANGER: Deletes all keys (and associated BLOB files) that contain the specified <substring>.

Command,Usage,Description
CONNECT,CONNECT -h <host> -p <port> [-cert <path> ...],"Reconnects or connects to a different server address, optionally updating client certificates."
DISCONNECT,DISCONNECT,Closes the current network connection without exiting the shell.
DUMP,DUMP [filename],Triggers the server to save the current database state to the specified file (or the default dump file).
LOAD,LOAD <filename>,Triggers the server to load and merge data from the specified file into the current store.
HELP,HELP,Displays the help message in the shell.
EXIT / QUIT,EXIT,Closes the connection and exits the client shell program.







