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
./json-db -s shell --cert client.crt --key client.key --ca-cert ca.crt -h 0.0.0.0 -p 9999
go run jsondb.go -s shell --cert client.crt --key client.key --ca-cert ca.crt -h 0.0.0.0 -p 9999

# Run the server on port 9999 (default)
./json-db -s db --cert server.crt --key server.key --ca-cert ca.crt -l initial_data.json -h 0.0.0.0 -p 9999
go run jsondb.go -s db --cert server.crt --key server.key --ca-cert ca.crt -l store_dump.json -h 0.0.0.0 -p 9999
 

-->

## DB server

```
go run main.go -s=db -h=0.0.0.0 -p=7000 -dt=30m -log=app.log -cert=server.crt -key=server.key -ca-cert=ca.crt -l=store_dump.json -dt=1h 
```

```
go run main.go -s=db -h=localhost -p=7000 -dt=30m -log=app.log -cert=server.crt -key=server.key -ca-cert=ca.crt -l=store_dump.json -dt=1h 
```

## DB shell

```
go run main.go -s=shell -cert=client.crt -key=client.key -ca-cert=ca.crt -h=192.168.1.10 -p=7000   
```

```
go run main.go -s=shell -cert=client.crt -key=client.key -ca-cert=ca.crt -h=localhost -p=7000   
```



# 📄 JSON DB Server and Client Shell Readme

This document provides a comprehensive guide to running the `jsondb` executable in both **DB Server Mode** and **Client Shell Mode**, including all necessary startup flags, their defaults, and a complete reference for all available shell commands.

---

## 1. DB Server Mode Startup Prefixes and Defaults

To run the server, use the flag `-s db` or `--mode db`. The server strictly uses Mutual TLS (mTLS) for security.

| Flag Short | Flag Long | Description | Default Value | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `-s` | `--mode` | **Mode:** Defines the execution type. | `db` | Must be `db` for server. |
| `-h` | `--host` | **Host:** The interface the server listens on. | `localhost` | Use `0.0.0.0` to listen on all interfaces. |
| `-p` | `--port` | **Port:** The TCP port the server listens on. | `9999` | |
| `-c` | `--cert` | **Server Certificate Path** | `server.crt` | Server's public certificate chain for mTLS. |
| `-k` | `--key` | **Server Private Key Path** | `server.key` | Server's private key for mTLS. |
| `-ca` | `--ca-cert` | **Root CA Certificate Path** | `ca.crt` | The CA used to sign both the server and client certificates. |
| `-df` | `--dump-file` | **Data Dump File:** Filename for persistence of the main data store. | `store_dump.json` | |
| `-sdf` | `--security-dump-file` | **Security Dump File:** Filename for persistence of Users, Groups, and ACLs. | `security_db_dump.json` | |
| `-l` | `--load` | **Load File:** Initial file to load data from on startup. | Value of `--dump-file` | If not specified, loads from the current dump file. |
| `-dt` | `--dump-time` | **Periodic Dump Interval:** Duration for automatically saving the store. | `30m` (30 minutes) | Set to `0s` to disable periodic dumping. |
| `--log` | N/A | **Log File:** Path to the server log file. | `server.log` | Use `""` (empty string) to disable file logging. |

### Example Server Startup
```bash
# Basic startup (assumes server.crt, server.key, ca.crt exist in the working directory)
./jsondb -s db

# Startup with custom port and disabled periodic dump
./jsondb -s db -p 8080 -dt 0s -log server.log

```

## 2. Client Shell Mode Startup Prefixes and Defaults

To run the client shell, use the flag `-s shell` or `--mode shell`. The client requires its own certificate and key to establish an mTLS connection with the server.

| Flag Short | Flag Long | Description | Default Value | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `-s` | `--mode` | **Mode:** Defines the execution type. | `shell` | Must be `shell` for client mode. |
| `-h` | `--host` | **Host:** The address of the DB server to connect to. | `localhost` | |
| `-p` | `--port` | **Port:** The port of the DB server to connect to. | `9999` | |
| `-c` | `--cert` | **Client Certificate Path** | `client.crt` | Client's public certificate chain for mTLS. |
| `-k` | `--key` | **Client Private Key Path** | `client.key` | Client's private key for mTLS. |
| `-ca` | `--ca-cert` | **Root CA Certificate Path** | `ca.crt` | The CA used to sign the server's certificate. |

### Example Client Shell Startup
```bash
# Basic client startup (will try to connect to localhost:9999)
./jsondb -s shell 

# Client connecting to a remote server with custom credentials
./jsondb -s shell -h remote.db.com -p 8080 -c user.crt -k user.key

```
## 3. Client Shell Commands (Extensive Guide)

Once the shell is running and a connection is established, the following commands are available. The prompt format is: `[<User ID>@<Host:Port> : <Client CN>]>`.

### 🔐 Authentication & Authorization

| Command | Usage | Description |
| :--- | :--- | :--- |
| `LOGIN` | `LOGIN <user_id> <password>` | Authenticates against the server to establish a session and get a token. **Requires successful mTLS first.** |
| `LOGOUT` | `LOGOUT` | Terminates the current application session and clears the local token/user ID. |

### 👤 User & Group Management (Admin Required)

These commands require a user to be logged in with **Admin (4)** permission on the `security_db` key.

| Command | Usage | Description |
| :--- | :--- | :--- |
| `CREATEUSER` | `CREATEUSER <id> <password>` | Creates a new user entry. The password is **Hashed** on the server. |
| `DELETEUSER` | `DELETEUSER <id>` | Deletes a user, removing them from all groups, ACLs, and invalidating their active session. |
| `VIEWUSER` | `VIEWUSER [id]` | View all user IDs, or details (excluding password hash) for a specific user ID. |
| `CHANGEPASSWORD` | `CHANGEPASSWORD <id> <new_password>` | Updates a user's password hash. |
| `UPDATEUSER` | `UPDATEUSER <id> -groups <group1,group2,...>` | **Replaces** the user's list of group memberships. |
| `CREATEGROUP` | `CREATEGROUP <name>` | Creates a new empty group. |
| `DELETEGROUP` | `DELETEGROUP <name>` | Deletes a group, cleaning up user memberships and group ACLs. |
| `VIEWGROUP` | `VIEWGROUP [name]` | View all group names, or the list of members for a specific group. |
| `UPDATEGROUP` | `UPDATEGROUP <name> -members <user1,user2,...>` | **Replaces** the group's list of members. *Note: This is a two-way update and will sync the users' group lists.* |
| `ADDUSERTOGROUP` | `ADDUSERTOGROUP <user_id> <group_name>` | Adds a specific user to a specific group (two-way update). |
| `REMOVEUSERFROMGROUP` | `REMOVEUSERFROMGROUP <user_id> <group_name>` | Removes a specific user from a specific group (two-way update). |

### 🔒 Access Control List (ACL) Management (Admin Required)

Permissions are defined by an integer: **0=NONE, 1=READ, 2=WRITE, 3=DELETE, 4=ADMIN**. These commands require a user to be logged in with **Admin (4)** permission on the `security_db` key.

| Command | Usage | Description |
| :--- | :--- | :--- |
| `SETPERM` | `SETPERM <key> <user/group> <id> <permission 0-4>` | Sets or updates an explicit permission level for a user or group on a specific data key. |
| `REMOVEPERM` | `REMOVEPERM <key> <user/group> <id>` | Removes the explicit permission entry for a user or group on a data key. |
| `UPDATEACL` | `UPDATEACL <key> <default_perm 0-4>` | Sets the **default permission** for a data key. This is applied if no explicit user/group match is found. |
| `VIEWACL` | `VIEWACL [key]` | View all keys that have explicit ACLs, or the details of the ACL for a specific key. |
| `DELETEACL` | `DELETEACL <key>` | Removes the entire explicit ACL object associated with a data key. |

### 📦 Key-Value Data Store Commands (Requires Token)

All data operations are subject to ACL checks based on the authenticated user's token.

| Command | Usage | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `SET` | `SET <key> <value/json>` | `WRITE` (2) | Sets a key with a simple string or a valid JSON structure. |
| `GET` | `GET <key>` | `READ` (1) | Retrieves the value associated with a key. |
| `DELETE` | `DELETE <key>` | `DELETE` (3) | Deletes a key-value entry. If it was a BLOB, the associated file is also removed. |
| `PUTBLOB` | `PUTBLOB <key> <local_file_path>` | `WRITE` (2) | Stores the contents of the local file on the server, saving metadata in the key-value store. |
| `GETBLOB` | `GETBLOB <key>` | `READ` (1) | Retrieves a BLOB and saves it to a local file named `retrieved_<key>_<originalName>`. |
| `DELETEBLOB` | `DELETEBLOB <key>` | `DELETE` (3) | Explicitly deletes a BLOB key and its associated file. |

### 🔎 Search & Bulk Delete (Requires Token)

| Command | Usage | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `SEARCH` | `SEARCH <string>` | `READ` (1) | Searches authorized keys and their values for a given string. |
| `SEARCHKEY` | `SEARCHKEY <substring>` | `READ` (1) | Searches authorized keys only for a given substring. |
| `DELETEKEY` | `DELETEKEY <substring>` | `DELETE` (3) | **DANGER:** Attempts to delete all keys containing the substring for which the user has `DELETE` permission. |

### ⚙️ System & Connection Commands (Local Shell Commands)

| Command | Usage | Notes | Description |
| :--- | :--- | :--- | :--- |
| `CONNECT` | `CONNECT -h <host> -p <port> -ca <path> -c <path> -k <path>` | Optional flags | Disconnects the current session (if any) and attempts a new mTLS connection with the specified parameters, updating the shell's configuration. |
| `DISCONNECT`| `DISCONNECT` | | Closes the current network connection and clears the session token. |
| `MYADDRESS` | `MYADDRESS` | | Displays the **Server (Remote) Address** and the **Client (Local) Address** of the active connection. |
| `CLIENTID` | `CLIENTID` | | Shows the Common Name (CN) from the client's mTLS certificate used for the current connection. |
| `DUMP` | `DUMP [filename]` | Admin Required | Triggers the server to perform a persistence dump for both data and security stores. |
| `LOAD` | `LOAD <filename>` | Admin Required | Triggers the server to load data from the specified file (merging it) and reload the security store (overwriting it). |
| `HELP` | `HELP` | | Displays the full list of shell commands. |
| `EXIT` / `QUIT` | `EXIT` / `QUIT` | | Closes the shell application. |


### Certificates 
###### for local development and self signed certificates
[san.cnf](https://github.com/ganeshkbhat/kvjsonDB/blob/main/san.cnf) - 
[certificates.sh](https://github.com/ganeshkbhat/kvjsonDB/blob/main/certificates.sh)