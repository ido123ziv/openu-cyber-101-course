# openu-cyber-101-course
OpenU course [20940](https://www.openu.ac.il/courses/20940.htm) final project, kerberos


# run commands

`python3 -m venv venv` 

`source venv/bin/activate`

`pip install -r requirements.txt`

# Components
* Auth Server
* Client
* Messaging Server

# Files explained
1. `port.info` ->  saves the port number (example: 1234)
2. `clients.info` -> clients data file with structure: `ID:Name:PasswordHash:LastSeen:`
3. `servers.info` -> servers data file with structure: `ID:Name:AESKey:`
4. `me.info` -> client data, see below for more details
5. `msg.info` -> messaging server data, see below


#### client data
```text
IP:PORT
NAME
UUID (HASH) 
```
#### messaging data
```text
PORT
NAME
UUID (HASH)
Key (base64)
```