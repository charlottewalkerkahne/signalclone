import os
import time
import utils
import crypto
import storage
import appconfig
import securesock
import application_data
from os.path import join, exists, isfile, isdir





class Client:
    def __init__(self, sock, addressbook, mailbox):
        self.sock = sock
        self.addressbook = addressbook
        self.handle = self.addressbook.local_username
        self.mailbox = mailbox


        self.conversations = {} #conversation_id: {peers: peer_list, messages: {timestamp: dm}}
        self.message_count = {} #conversation_id: current_message_count
        self.new_messages = {} #conversation_id: [(source, dm)]

        self.conversation_names = {} #name: convo_id
        self.new_conversations = [] #conversation_id

        self.directory = {}
        self.attachments = {}

    def connect_to_server(self, server_addr):
        peer_id = self.get_id_from_username(str(server_addr))
        try:
            self.sock.connect(server_addr, peer_id)
            return None
        except Exception as err:
            return err

    def handshake_complete(self):
        peer_id = self.sock.connection_id
        return self.sock.channel_secured(peer_id)

    def get_username_from_id(self, id):
        return self.addressbook.fetch_username_by_id(id)

    def get_id_from_username(self, username):
        return self.addressbook.fetch_id_by_username(username)

    def get_convo_id_from_name(self, convo_id):
        return self.conversation_names[convo_id]

    def store_message(self, source_id, convo_id, timestamp, dm, is_attachment):
        if convo_id in self.message_count:
            self.message_count[convo_id] += 1
        else:
            self.message_count[convo_id] = 0
        self.mailbox.add_message(source_id, convo_id, dm, timestamp, self.message_count[convo_id], is_attachment)

    def save_conversation(self, convo_id, users, name=None):
        self.mailbox.add_conversation(convo_id, users, name)

    def load_conversations(self):
        return self.mailbox.get_conversation_list()

    def delete_message(self, convo_id, msg_num):
        self.mailbox.remove_message(convo_id, msg_num)
        #del self.conversations[convo_id]["messages"][]

    def delete_conversation(self, convo_id):
        #will delete all messages with convo_id
        pass

    #checks to see if there is already a conversation id associated with a group of peers
    #useful to prevent duplicate conversations
    def get_existing_convo_id(self, peer_id_list):
        sorted_list = sorted(peer_id_list)
        for conversation_id, conversation_information in self.conversations.items():
            if conversation_information["peers"] == sorted_list:
                return conversation_id
        return None

    def load_messages(self, conversation_id):
        message_list = self.mailbox.fetch_by_conversation(conversation_id)
        self.message_count[conversation_id] = 0
        messages = []
        if message_list is None:
            return []
        for (source_id, message, timestamp, id, attachment_name) in message_list:
            source_id = utils.decode_64(source_id)
            if id > self.message_count[conversation_id]:
                self.message_count[conversation_id] += 1
            messages.append((source_id, message, timestamp, id, attachment_name))
        messages.sort(key = lambda x: x[3])
        return message_list

    def fetch_messages_from_server(self):
        request_type = application_data.REQUEST_UNDELIVERED_MESSAGES
        info_request = application_data.encode_info_request(self.sock.keyring.identity_id, request_type)
        self.sock.write(info_request, self.sock.connection_id)

    def post_prekey_bundle(self):
        self.sock.send_prekey_bundle_post(50)

    def update(self):
        self.sock.update()
        new_application_data = self.sock.read()
        if new_application_data is not None:
            encoded_data, source_id, dest_id = new_application_data
            assert(source_id is not None)
            self.process_application_data(encoded_data, source_id)

    def decode(self, encoded_data):
        decoded_data = application_data.decode_data(encoded_data)
        return decoded_data

    def valid_sender(self, header, source_id):
        if header['SOURCE_ID'] != utils.encode_64(source_id):
            return False
        if header['MESSAGE_TYPE'] == application_data.TYPE_DM: #servers cannot send DMs
            if source_id == self.sock.connection_id:
                return False
        elif header['MESSAGE_TYPE'] == application_data.TYPE_INFO_REQUEST:
            print("Clients may only send info requests")
            return False
        elif header['MESSAGE_TYPE'] == application_data.TYPE_INFO_RESPONSE:
            if source_id != self.sock.connection_id:
                print("Only servers may send info responses")
                return False
        elif header['MESSAGE_TYPE'] == application_data.TYPE_DM_CONTROL:
            if source_id == self.sock.connection_id:
                print("Only clients may send dm control messages")
                return False
        elif header['MESSAGE_TYPE'] == application_data.TYPE_BROADCAST:
            if source_id != self.sock.connection_id:
                print("Only servers may send broadcasts")
                return False
        return True

    def process_application_data(self, encoded_data, source_id):
        decoded_data = self.decode(encoded_data)
        if decoded_data is None:
            self.send_decoding_error(source_id)
        else:
            decoded_header = decoded_data[0]
            decoded_body = decoded_data[1]
            if not self.valid_sender(decoded_header, source_id):
                self.send_decoding_error(source_id)
            else:
                msg_type = decoded_header['MESSAGE_TYPE']
                self.process_body(source_id, msg_type, decoded_body)

    def process_body(self, source_id, msg_type, body):
        if msg_type == application_data.TYPE_DM:
            self.process_dm(source_id, body)
        elif msg_type == application_data.TYPE_INFO_REQUEST:
            self.process_info_request(source_id, body)
        elif msg_type == application_data.TYPE_INFO_RESPONSE:
            self.process_info_response(source_id, body)
        elif msg_type == application_data.TYPE_DM_CONTROL:
            self.process_dm_control(source_id, body)
        elif msg_type == application_data.TYPE_BROADCAST:
            self.process_broadcast(source_id, body)

    def process_dm_control(self, source_id, body):
        if application_data.is_valid_dm_control(body):
            if body['CONTROL_TYPE'] == application_data.DM_CONTROL_NEW_CONVO:
                salt = utils.decode_64(body['SALT'])
                participant_list = list(map(lambda i: utils.decode_64(i), body['CONTENT']))
                verified_usernames = {}
                for participant_id in participant_list:
                    if participant_id != self.sock.keyring.identity_id:
                        participant_handle = self.get_username_from_id(participant_id)
                        if participant_handle is not None:
                            verified_usernames[participant_handle] = participant_id
                        else:
                            return False
                    else:
                        verified_usernames[self.handle] = self.sock.keyring.identity_id
                convo_id = crypto.sha256sum(salt + b"".join(sorted(participant_list)))
                self.conversations[convo_id] = {"peers": participant_list, "messages": []}
                self.new_conversations.append((convo_id, verified_usernames))
        else:
            self.send_decoding_error(source_id)

    def process_dm(self, source_id, body):
        if application_data.is_valid_dm(body):
            convo_id = utils.decode_64(body['CONVERSATION_ID'])
            attachment_name = body['ATTACHMENT']
            timestamp = body["TIMESTAMP"]
            msg_content = body['CONTENT']
            if convo_id in self.conversations:
                if source_id in self.conversations[convo_id]["peers"]:
                    self.store_message(source_id, convo_id, timestamp, msg_content, attachment_name)
                    self.conversations[convo_id]["messages"].append((source_id, msg_content, timestamp, self.message_count[convo_id], attachment_name))
                    if convo_id not in self.new_messages:
                        self.new_messages[convo_id] = []
                    self.new_messages[convo_id].append((source_id, body))
            else:
                print("Unrecognized conversation id")
        else:
            self.send_decoding_error(source_id)

    def process_broadcast(self, source_id, body):
        pass

    def process_info_request(self, source_id, body):
        assert((True==False) and "We should not have made it to this...")

    def process_info_response(self, source_id, body):
        print("Not implemented")

    def send_decoding_error(self, destination):
        print("Cannot send decoding error - not implemented")
        pass

    def start_conversation(self, usernames):
        peer_id_list = []
        for username in usernames:
            fetched_id = self.get_id_from_username(username)
            assert(fetched_id is not None)
            if fetched_id is not None:
                peer_id_list.append(fetched_id)
        existing_convo_id = self.get_existing_convo_id(peer_id_list)
        if existing_convo_id is not None:
            self.send_dm(existing_convo_id)
        else:
            #sort peer_id list and then hash to get the convo_id
            convo_id_salt = os.urandom(32)
            new_convo_id = crypto.sha256sum(convo_id_salt + b''.join(sorted(peer_id_list)))
            source_id = self.get_id_from_username(self.handle)
            dm_control = application_data.encode_dm_control(source_id, application_data.DM_CONTROL_NEW_CONVO, peer_id_list, convo_id_salt)
            self.conversations[new_convo_id] = {"peers": peer_id_list, "messages": []}
            if len(peer_id_list) > 2: #because we include our own handle
                peers = peer_id_list[:]
                peers.remove(source_id)
                self.sock.send_broadcast_request_message(dm_control, peers)
            else:
                for peer_id in peer_id_list:
                    if peer_id != source_id:
                        self.sock.write(dm_control, peer_id)
            return new_convo_id

    def send_dm(self, convo_id, message, attachment=""):
        source_id = self.get_id_from_username(self.handle)
        timestamp = time.mktime(time.gmtime())
        dm = application_data.encode_dm(source_id, convo_id, timestamp, attachment, message)
        recipient_list = self.conversations[convo_id]["peers"]
        if len(recipient_list) > 2:
            peers = recipient_list[:]
            peers.remove(source_id)
            self.sock.send_broadcast_request_message(dm, peers)
        else:
            for recipient in self.conversations[convo_id]["peers"]:
                if recipient != source_id: #dont try to send message to myself
                    #todo maybe get an error code here to know if it sent correctly?
                    self.sock.write(dm, recipient)
        self.store_message(source_id, convo_id, timestamp, message, attachment)
        return (attachment, timestamp, message, source_id, convo_id)

    def disconnect(self):
        self.sock.shutdown()

    def get_broadcast_messages(self):
        pass

    def save_attachment(self, file_bytes, path):
        if not exists(appconfig.DEFAULT_ATTACHMENT_DIR):
            return False
        full_path = os.path.join(appconfig.DEFAULT_ATTACHMENT_DIR, path)
        decompressed_bytes = utils.decompress(utils.decode_64(file_bytes))
        if not exists(full_path):
            with open(full_path, "wb") as filewriter:
                filewriter.write(decompressed_bytes)
            return True
        else:
            return False

    def load_attachment(self, path):
        if exists(path):
            file_bytes = b""
            with open(path, "rb") as filereader:
                file_bytes = filereader.read()
            compressed_bytes = utils.compress(file_bytes)
            return utils.encode_64(compressed_bytes)
        return None

    def name_conversation(self, convo_id, new_name):
        if convo_id in self.conversations:
            if new_name in self.conversation_names:
                return False
            else:
                self.conversation_names[new_name] = convo_id
        else:
            return False



def get_client(handle, db_connection):
    ab = storage.AddressBook(handle, db_connection)
    identity_id = ab.fetch_id_by_username(handle)
    ab.set_active_username(handle)
    ks = storage.KeyStorage(identity_id, db_connection)
    keyring = crypto.MemoryKeyStore(ks, identity_id)
    mb = storage.MessageStorage(identity_id, db_connection)
    keyring.load_peers(ab)
    sock = securesock.SecureSock(utils.init_socket(), keyring)
    return Client(sock, ab, mb)



