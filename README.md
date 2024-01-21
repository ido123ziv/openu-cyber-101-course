# openu-cyber-101-course
OpenU course [20940](https://www.openu.ac.il/courses/20940.htm) final project, kerberos


# run commands

`python3 -m venv venv` 

`source venv/bin/activate`

`pip install -r requirements.txt`

# Files explained
1. `port.info` ->  saves the port number (example: 1234)
2. `clients.info` -> clients data file with structure: `ID:Name:PasswordHash:LastSeen:`
3. `servers.info` -> servers data file with structure: `ID:Name:AESKey:`