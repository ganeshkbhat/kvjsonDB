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


go run main.go -s=db -h=0.0.0.0 -p=8080 -dt=30m -log=app.log -cert=server.crt -key=server.key -ca-cert=ca.crt -l=initial_data.json -dt=1h 


go run main.go -s=shell -cert=client.crt -key=client.key -ca-cert=ca.crt -h=192.168.1.10 -p=8888   




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





