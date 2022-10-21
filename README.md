
# A Python implementation of a chat server and client using the signal protocol. Currently not in a running state - have not had the time to fix it 

***
### Installation requirements

#### cryptography (https://cryptography.io)

#### PyQt5 (https://doc.qt.io/qtforpython)
***

### Installation instructions

```commandline
cd <installation dir>
git clone https://charlottewalkerkahne/signalclone
cd signalclone
```
Keys 
```commandline
python3 -i setup_tests.py
```
```python
>>> do_first_time_setup()
```
Now there should be four databases in /tmp/TESTS:

client_0.sqlite3

client_1.sqlite3

client_2.sqlite3

('127.0.0.1', 9080)

Each database should have two pairs of private identity keys (one for x3dh and one for signing). 
There should also be a public ed25519 key and x25519 key for each of the other databases.

## Usage
To run the server:
```commandline
python3 server.py
```
And the client:
```commandline
python3 clientui.py
```

To connect to the server, enter one of client_0, client_1, or client_2 in the login name field.

***
# DISCLAIMER: I AM NOT A PROFESSIONAL! I made this project for fun, not because I think it should ever be used in any situation that requires real security.
