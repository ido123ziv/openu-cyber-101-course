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

# Overview 
- `Client --> Auth Server: IDs, Nonce`
- `Auth Server --> Client: EKc(Kc,s, Nonce), Ticket`
- `Client -->Msg Server: Ticket, Authenticator`
- `Msg Server -->Client: KeyAck`
- `Client --> Msg Server: EKc,s(Message)`
- `Msg Server -->Client: MsgAck`

# Files explained
1. `port.info` ->  saves the port number (example: 1234)
2. `clients.info` -> clients data file with structure: `ID:Name:PasswordHash:LastSeen:`
3. `servers.info` -> servers data file with structure: `ID:Name:AESKey:`
4. `me.info` -> client data, see [below](#client-data) for more details
5. `msg.info` -> messaging server data, see [below](#messaging-data)
6. `srv.info` -> servers addresses and ports


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