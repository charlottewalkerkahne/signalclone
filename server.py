import os
import time
import utils
import crypto
import storage
import tracemalloc
from time import sleep
import application_data
from threading import Thread
from securesock import SecureSock
from multiprocessing import Queue



BINDWAIT=5

CONNECT_TIMEOUT = 2

class Server:
    def __init__(self, keyring, sock, addressbook, message_store):
        self.sock = sock
        self.clients = {} #peer_id : SecureSock obj
        self.pending_sockets = {}
        self.closed_sockets = []
        self.accept_thread = None
        self.accepting = True
        self.addressbook = addressbook
        self.keyring = keyring
        self.message_store = message_store
        self.application_q = Queue()
        self.running = False
        self.ticktock_thread = None
    def listen_on(self, address):
        self.running = True
        while True:
            try:
                self.sock.bind(address)
                break
            except OSError:
                sleep(BINDWAIT)
        self.sock.listen()
    def start_accepting(self):
        self.accept_thread = Thread(target=self.accept)
        self.accept_thread.start()
        self.ticktock_thread = Thread(target=self.tick)
        self.ticktock_thread.start()
    def should_accept(self):
        return self.accepting
    def is_valid_id(self, id):
        if id in self.clients:
            return False
        if id not in self.keyring.peer_identity_ed_keys:
            return False
        return True
    def accept(self):
        self.sock.settimeout(1)
        while self.running:
            if self.should_accept():
                new_connection, addr = None, None
                try:
                    new_connection, addr = self.sock.accept()
                except(TimeoutError):
                    pass
                except(OSError):
                    break
                if new_connection is not None:
                    new_client = SecureSock(new_connection, self.keyring, self.application_q)
                    self.pending_sockets[addr] = (new_client, time.time())
    def stop(self):
        self.accepting = False
        self.running = False
    def route_message(self, frame, source_id, dest_id):
        if dest_id == self.keyring.identity_id:
            self.handle_server_data(frame, source_id)
        else:
            if dest_id in self.clients:
                destination = self.clients[dest_id]
                destination.raw_send(frame)
            else:
                if source_id in self.clients:
                    self.message_store.add_message(dest_id, frame)
    def handle_server_data(self, data, source_id):
        decoded_data = application_data.decode_data(data)
        if decoded_data is not None:
            header, body = decoded_data
            if header["SOURCE_ID"] != utils.encode_64(source_id):
                pass
            else:
                message_type = header["MESSAGE_TYPE"]
                if message_type == application_data.TYPE_INFO_REQUEST:
                    request_type = body["REQUEST_TYPE"]
                    if request_type == application_data.REQUEST_UNDELIVERED_MESSAGES:
                        messages = self.message_store.fetch_messages(source_id)
                        messages.sort(key = lambda x: x[1])
                        for undelivered_message in messages:
                            self.clients[source_id].raw_send(undelivered_message[0])
                    elif request_type == application_data.ACK_FETCHED_MESSAGES:
                        pass
                    else:
                        print("No other request types are implemented for the server")
                else:
                    print("No other application message types are implemented for the server")
                    pass
    def process_application_data(self, frame, source, destination):
        self.route_message(frame, source, destination)
    def update_sock(self, sock):
        if not sock.closed:
            sock.update()
        else:
            self.closed_sockets.append(sock.connection_id)
    def tick(self):
        while self.running:
            clients_iterable = self.clients.items()
            for peer_id,sock_obj in clients_iterable:
                self.update_sock(sock_obj)
            pending_sock_addresses = list(self.pending_sockets.keys())
            for addr in pending_sock_addresses:
                sock_obj = self.pending_sockets[addr][0]
                timestamp = self.pending_sockets[addr][1]
                self.update_sock(sock_obj)
                if sock_obj.connection_id is not None:
                    if sock_obj.channel_secured(sock_obj.connection_id):
                        if self.is_valid_id(sock_obj.connection_id):
                            self.clients[sock_obj.connection_id] = sock_obj
                            del self.pending_sockets[addr]
                        else:
                            del self.pending_sockets[addr]
                    else:
                        current_time = time.time()
                        if current_time - timestamp >= CONNECT_TIMEOUT:
                            del self.pending_sockets[addr]
                else:
                    current_time = time.time()
                    if current_time - timestamp >= CONNECT_TIMEOUT:
                        del self.pending_sockets[addr]
            for id in self.closed_sockets:
                if id in self.clients:
                    del self.clients[id]
            del pending_sock_addresses
            self.closed_sockets = []
            self.tock()
    def tock(self):
        clients_iterable = self.clients.items()
        for peer_id, client in clients_iterable:
            new_data = client.read()
            if new_data is not None:
                data,source,destination = new_data
                self.process_application_data(data, source, destination)
        sleep(.001) #slow server update thread





def handle_server_commands(server):
    prompt = "> "
    while server.running:
        command_success = False
        while not command_success:
            command = input(prompt)
            command = command.lower().split(' ')
            if len(command) == 1:
                command = command[0]
                if command == "stop":
                    server.stop()
                    command_success = True
                else:
                    print("\'{}\' is not a recognized command".format(command))


def start_server(address, addressbook, keyring, ms):
    sock = utils.init_socket()
    server = Server(keyring, sock, addressbook, ms)
    server.listen_on(address)
    server.start_accepting()
    handle_server_commands(server)
    server.accept_thread.join()
    server.ticktock_thread.join()

def setup_server():
    server_addr = ('127.0.0.1', 9080) #default
    storage_path = "/tmp/TESTS/('127.0.0.1', 9080).sqlite3"
    db_connection = storage.load_storage(storage_path)
    ab = storage.AddressBook(str(server_addr), db_connection)
    identity_id = ab.fetch_id_by_username(str(server_addr))
    ab.set_active_username(str(server_addr))
    ks = storage.KeyStorage(identity_id, db_connection)
    keyring = crypto.MemoryKeyStore(ks, identity_id)
    keyring.load_peers(ab)
    ms = storage.ServerStorage(identity_id, db_connection)
    start_server(server_addr, ab, keyring, ms)

if __name__=='__main__':
    tracemalloc.start()
    setup_server()
