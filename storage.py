import threading
import sqlite3
from os.path import exists, isfile
from os import remove
from base64 import b64encode, b64decode
import utils

TESTING_PATH = "TESTDATABASE.db"


DEFAULT_STORAGE_PATH = "/tmp/TESTS/"
DEFAULT_MAX_BUNDLE_AGE = 2592000 #30 days


KEY_TYPE_ED = 0x00
KEY_TYPE_DH = 0x01
KEY_TYPE_SPK = 0x03
KEY_TYPE_OTK = 0x04

class ThreadSafeCursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.lock = threading.Lock()
    def execute(self, statement, *args):
        self.lock.acquire()
        self.cursor.execute(statement, *args)
        self.lock.release()
    def fetchall(self):
        self.lock.acquire()
        fetched = self.cursor.fetchall()
        self.lock.release()
        return fetched
    def fetchone(self):
        self.lock.acquire()
        fetched = self.cursor.fetchone()
        self.lock.release()
        return fetched

class ThreadSafeConnection:
    def __init__(self, db_connection):
        self.db_connection = db_connection
        self.lock = threading.Lock()
    def cursor(self):
        self.lock.acquire()
        safe_cursor = ThreadSafeCursor(self.db_connection.cursor())
        self.lock.release()
        return safe_cursor
    def commit(self):
        self.lock.acquire()
        self.db_connection.commit()
        self.lock.release()


def storage_exists(storage_path):
    return exists(storage_path) and isfile(storage_path)

def create_keystorage(cursor):
    cursor.execute('''CREATE TABLE keystorage (identity_id text, key_id text, key_bytes blob, key_type text)''')
    cursor.execute('''CREATE TABLE ratchetstorage (session_id text, peer_id text, ratchet_info text)''')

def create_addressbook(cursor):
    cursor.execute('''CREATE TABLE addressbook (identity_id text, username text, is_server integer)''')

def create_serverstorage(cursor):
    cursor.execute('''CREATE TABLE serverstorage (dest_id text, message_bytes blob, message_number integer)''')


def create_messagestorage(cursor):
    cursor.execute('''CREATE TABLE messagestorage (source_id text, conversation_id text, message text, timestamp real, message_id integer, attachment_name text)''')
    cursor.execute('''CREATE TABLE conversations (conversation_id string, participant_id_list string, name string)''')

def remove_storage(storage_path):
    remove(storage_path)

def encode_64(input_bytes):
    return b64encode(input_bytes).decode()

def decode_64(input_str):
    return b64decode(input_str.encode())

def create_storage(storage_path=DEFAULT_STORAGE_PATH, server=False):
    con = sqlite3.connect(storage_path, check_same_thread=False)
    cur = con.cursor()
    create_keystorage(cur)
    create_addressbook(cur)
    if server:
        create_serverstorage(cur)
    else:
        create_messagestorage(cur)
    con.commit()
    return con


def load_storage(storage_path, server=False):
    if exists(storage_path):
        return ThreadSafeConnection(sqlite3.connect(storage_path, check_same_thread=False))
    return None



#username for the server is just the server address
class AddressBook:
    def __init__(self, local_username, connection):
        self.connection = connection
        self.cursor = self.connection.cursor()
        self.local_username = local_username #might be None
        self.identities = {} #cache username: identity
        self.usernames = {} #cache  identity: username
        self.is_a_server = {}#identity: bool
    def get_all_peer_ids(self):
        self.cursor.execute("SELECT * FROM addressbook")
        peer_list = self.cursor.fetchall()
        if len(peer_list) == 0:
            return None
        else:
            decoded_ids = []
            for (id, username, is_server) in peer_list:
                decoded_id = utils.decode_64(id)
                self.identities[username] = decoded_id
                self.usernames[decoded_id] = username
                self.is_a_server[decoded_id] = is_server == 1
                decoded_ids.append(decoded_id)
            return decoded_ids
    def get_number_of_clients(self): #includes local user
        return self.cursor.rowcount()
    def set_active_username(self, username):
        self.local_username = username
    def add_contact(self, identity_id, username, is_server=False):
        encoded_identity_id = encode_64(identity_id)
        if not is_server:
            is_server = 0
        else:
            is_server = 1
        self.cursor.execute("INSERT INTO addressbook VALUES (?,?, ?)", (encoded_identity_id, username, is_server))
        self.usernames[identity_id] = username
        self.identities[username] = identity_id
        self.sync()
    def update_contact_username(self, identity_id, new_username):
        encoded_identity_id = encode_64(identity_id)
        #changes the username associated with peer_id
        self.cursor.execute("UPDATE addressbook SET username=:new_username WHERE identity_id=:identity_id",
                            {"new_username":new_username, "identity_id":encoded_identity_id}
        )
        if identity_id in self.usernames:
            old_username = self.usernames[identity_id]
            self.usernames[identity_id] = new_username
            self.identities[new_username] = identity_id
            if old_username in self.identities:
                del self.identities[old_username]
        self.sync()
    """
    def update_contact_identity(self, new_identity_id, username):
        encoded_identity_id = encode_64(new_identity_id)
        self.cursor.execute("UPDATE addressbook SET identity_id=:identity_id WHERE username=:username",
                            {"username": username, "identity_id": encoded_identity_id}
        )
        if username in self.identities:
            old_identity = self.identities[username]
            self.identities[username] = new_identity_id
            self.usernames[new_identity_id] = username
            if old_identity in self.usernames:
                del self.usernames[old_identity]
        self.sync()
    """
    def fetch_username_by_id(self, identity_id):
        if identity_id in self.usernames:
            return self.usernames[identity_id]
        encoded_identity_id = encode_64(identity_id)
        self.cursor.execute("SELECT username FROM addressbook WHERE identity_id=:identity_id",
                            {"identity_id":encoded_identity_id}
        )
        username_list = self.cursor.fetchall()
        if len(username_list) == 1:
            username = username_list[0][0]
            #add to cache first
            self.usernames[identity_id] = username
            return username
        else:
            return None
    def fetch_id_by_username(self, username):
        if username in self.identities:
            return self.identities[username]
        self.cursor.execute("SELECT identity_id FROM addressbook WHERE username=:username",
                            {"username":username}
        )
        identity_id_list = self.cursor.fetchall()
        assert(len(identity_id_list) <= 1)
        if len(identity_id_list) == 1:
            identity = decode_64(identity_id_list[0][0])
            self.identities[username] = identity
            return identity
        else:
            return None
    def remove_contact(self, identity_id):
        encoded_identity_id = encode_64(identity_id)
        self.cursor.execute("DELETE FROM addressbook WHERE identity_id=:identity_id",
                            {"identity_id":encoded_identity_id}
        )
        if identity_id in self.usernames:
            username = self.usernames[identity_id]
            del self.usernames[identity_id]
            if username in self.identities:
                del self.identities[username]
        self.sync()
    def close(self):
        self.sync()
        self.connection.close()
    def sync(self):
        self.connection.commit()

#key_types = [ ed_key, dh_key, spk, otk ]
#key_id is the bytes of the 32 byte public key
#identity_id | key_id | key_bytes | key_type
class KeyStorage:
    def __init__(self, user_id, connection):
        self.user_id = user_id
        self.connection = connection
        self.cursor = self.connection.cursor()
    def insert_new_key(self, identity_id, key_id, key_bytes, key_type):
        #if identity_id is local_id then key_bytes is a private key
        #if the key is an spk then key_bytes = concat(spk_bytes, spk_sig)
        #if identity_id is not local_id then key_bytes is a public_key
        key_type = key_type.lower()
        encoded_identity_id = utils.encode_64(identity_id)
        encoded_key_id = utils.encode_64(key_id)
        self.cursor.execute("INSERT INTO keystorage VALUES (?, ?, ?, ?)",
                            (encoded_identity_id, encoded_key_id, key_bytes, key_type))
        self.sync()
    def insert_new_ratchet(self, session_id, peer_id, ratchet_info):
        encoded_id = utils.encode_64(session_id)
        encoded_peer_id = utils.encode_64(peer_id)
        self.cursor.execute("INSERT INTO ratchetstorage VALUES (?,?, ?)",(encoded_id, encoded_peer_id, ratchet_info))
        self.sync()
    def fetch_ratchet_by_session_id(self, session_id):
        encoded_id = utils.encode_64(session_id)
        self.cursor.execute("SELECT * from ratchetstorage WHERE session_id=:session_id",
                            {"session_id":encoded_id})
        ratchets = self.cursor.fetchall()
        assert(len(ratchets) <= 1)
        if len(ratchets) == 0:
            return None
        return (utils.decode_64(ratchets[0][0]), utils.decode_64(ratchets[0][1]), ratchets[0][2])
    def fetch_ratchet_by_peer_id(self, peer_id):
        encoded_id = utils.encode_64(peer_id)
        self.cursor.execute("SELECT * from ratchetstorage WHERE peer_id=:peer_id",
                            {"peer_id": encoded_id})
        ratchets = self.cursor.fetchall()
        assert (len(ratchets) <= 1)
        if len(ratchets) == 0:
            return None
        return (utils.decode_64(ratchets[0][0]), utils.decode_64(ratchets[0][1]), ratchets[0][2])
    def update_ratchet(self, session_id, ratchet_info):
        encoded_id = utils.encode_64(session_id)
        self.cursor.execute("UPDATE ratchetstorage SET ratchet_info=:ratchet_info WHERE session_id=:session_id",
                            {"session_id":encoded_id, "ratchet_info":ratchet_info})
        self.sync()
    def delete_session(self, session_id):
        encoded_id = utils.encode_64(session_id)
        self.cursor.execute("DELETE FROM ratchetstorage WHERE session_id=:session_id",
                            {"session_id":encoded_id})
        self.sync()
    def fetch_by_id(self, identity_id, key_id):
        encoded_identity_id = utils.encode_64(identity_id)
        encoded_key_id = utils.encode_64(key_id)
        self.cursor.execute(
            "SELECT key_bytes FROM keystorage WHERE identity_id=:identity_id AND key_id=:key_id",
            {"identity_id":encoded_identity_id, "key_id":encoded_key_id}
        )
        key_list = self.cursor.fetchall()
        if len(key_list) == 1:
            return key_list[0][0]
        else:
            return None
    def fetch_by_type(self, identity_id, key_type):
        #will return all keys belonging to user with identity_id of type key_type
        #this is useful for returning all otk keys or spk keys during the initial setup
        key_type = key_type.lower()
        encoded_identity_id = encode_64(identity_id)
        self.cursor.execute(
            "SELECT key_bytes FROM keystorage WHERE identity_id=:identity_id AND key_type=:key_type",
            {"identity_id":encoded_identity_id, "key_type":key_type}
        )
        fetched_keys = self.cursor.fetchall()
        if len(fetched_keys) == 0:
            return None
        else:
            return fetched_keys[0][0]
    def remove_key(self, identity_id, key_id):
        encoded_identity_id = encode_64(identity_id)
        encoded_key_id = encode_64(key_id)
        self.cursor.execute(
            "DELETE FROM keystorage WHERE identity_id=:identity_id AND key_id=:key_id",
            {"identity_id": encoded_identity_id, "key_id": encoded_key_id}
        )
        self.sync()
    def sync(self):
        self.connection.commit()



class ServerStorage:
    def __init__(self, id, connection):
        self.id = id
        self.connection = connection
        self.cursor = self.connection.cursor()
        self.message_cache = {} # dest_id: message_list holds onto messages in the cache for a set amount of time
        self.message_count = {} # dest_id: count used to keep track of message order

    #adds a message addressed to dest_id
    def add_message(self, dest_id, message_bytes):
        if dest_id not in self.message_count:
            self.message_count[dest_id] = 0
        encoded_dest_id = encode_64(dest_id)
        self.cursor.execute("INSERT INTO serverstorage VALUES(?, ?, ?)",
                         (encoded_dest_id, message_bytes, self.message_count[dest_id])
        )
        if dest_id in self.message_cache:
            self.message_cache[dest_id].append((message_bytes, self.message_count[dest_id]))
        else:
            self.message_cache[dest_id] = [(message_bytes, self.message_count[dest_id])]
        self.message_count[dest_id] += 1
        self.sync()

    #fetches all messages addressed to dest_id
    #message order should be handled by the application
    def fetch_messages(self, dest_id):
        encoded_dest_id = utils.encode_64(dest_id)
        if dest_id in self.message_cache:
            messages = self.message_cache[dest_id]
            del self.message_cache[dest_id]
            self.delete_messages(dest_id)
            return messages
        self.cursor.execute("SELECT message_bytes, message_number FROM serverstorage WHERE dest_id=:dest_id",
                         {"dest_id": encoded_dest_id}
        )
        message_list = self.cursor.fetchall()
        self.delete_messages(dest_id)
        self.sync()
        return message_list


    #deletes all messages addressed to dest_id
    def delete_messages(self, dest_id):
        if dest_id in self.message_cache:
            del self.message_cache[dest_id]
        encoded_dest_id = utils.encode_64(dest_id)
        self.cursor.execute("DELETE FROM serverstorage WHERE dest_id=:dest_id", {"dest_id": encoded_dest_id})
        self.message_count[dest_id] = 0
        self.sync()
    

    def sync(self):
        self.connection.commit()



class MessageStorage:
    def __init__(self, user_id, connection):
        self.user_id = user_id
        self.connection = connection
        self.cursor = self.connection.cursor()
        self.conversation_cache = {} #conversation_id: list(message_id, source_id, message_text)
    def add_message(self, source_id, conversation_id, message_text, timestamp, message_id, attachment_name):
        if attachment_name is None:
            attachment_name = ""
        encoded_source_id = encode_64(source_id)
        encoded_conversation_id = encode_64(conversation_id)
        self.cursor.execute("INSERT INTO messagestorage VALUES (?, ?, ?, ?, ?, ?)",
                            (encoded_source_id, encoded_conversation_id, message_text, timestamp, message_id, attachment_name))
        if conversation_id in self.conversation_cache:
            self.conversation_cache[conversation_id].append((encoded_source_id, message_text, message_id, timestamp, attachment_name))
        else:
            self.conversation_cache[conversation_id] = [(encoded_source_id, message_text, message_id, timestamp, attachment_name)]
        self.sync()
    def add_conversation(self, conversation_id, participant_id_list, convo_name=None):
        encoded_conversation_id = encode_64(conversation_id)
        encoded_participant_id_list = ' '.join(list(map(utils.encode_64, participant_id_list)))
        self.cursor.execute("INSERT INTO conversations VALUES (?, ?, ?)",
                            (encoded_conversation_id, encoded_participant_id_list, convo_name))
        self.sync()
    def get_conversation_list(self):
        self.cursor.execute("SELECT * from conversations")
        conversation_list = self.cursor.fetchall()
        if len(conversation_list) > 0:
            decoded_conversation_list = []
            for (id,participants,name) in conversation_list:
                decoded_participants = list(map(utils.decode_64, participants.split(' ')))
                decoded_conversation_list.append((utils.decode_64(id), decoded_participants, name))
            return decoded_conversation_list
        else:
            return []
    def fetch_by_conversation(self, conversation_id): #returns a list
        if conversation_id in self.conversation_cache:
            return self.conversation_cache[conversation_id]
        encoded_conversation_id = encode_64(conversation_id)
        self.cursor.execute(
            "SELECT source_id, message, message_id, timestamp, attachment_name FROM messagestorage WHERE conversation_id=:conversation_id",
            {"conversation_id":encoded_conversation_id}
        )
        message_list = self.cursor.fetchall()
        if len(message_list) > 0:
            return message_list
        else:
            return None
    def fetch_by_id(self, conversation_id, message_id): #returns a single message or None if none found
        encoded_conversation_id = utils.encode_64(conversation_id)
        self.cursor.execute(
            "SELECT message from messagestorage WHERE conversation_id=:convo_id AND message_id=:msg_id",
            {"convo_id": encoded_conversation_id, "msg_id": message_id}
        )
        message = self.cursor.fetchall()
        if len(message) == 1:
            return message[0][0]
        else:
            return None

    def remove_message(self, conversation_id, message_id):
        if conversation_id in self.conversation_cache:
            index = 0
            for message_tuple in self.conversation_cache[conversation_id]:
                if message_tuple[0] == message_id:
                    break
                else:
                    index += 1
            self.conversation_cache[conversation_id].remove(self.conversation_cache[conversation_id][index])
        encoded_conversation_id = encode_64(conversation_id)
        self.cursor.execute(
            "DELETE FROM messagestorage WHERE conversation_id=:conversation_id AND message_id=:message_id",
            {"conversation_id":encoded_conversation_id, "message_id": message_id}
        )
        self.sync()

    def remove_conversation(self, conversation_id):
        encoded_conversation_id = utils.encode_64(conversation_id)
        self.cursor.execute(
            "DELETE FROM conversations WHERE conversation_id=:convo_id",
            {"convo_id":encoded_conversation_id}
        )
        self.cursor.execute(
            "DELETE FROM messagestorage WHERE conversation_id=:convo_id",
            {"convo_id":encoded_conversation_id}
        )
        self.sync()

    def sync(self):
        self.connection.commit()

