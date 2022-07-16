import crypto
import install
import storage
from os import mkdir, rename, system
from os.path import exists, join, isdir
from sys import platform

import storage

DEFAULT_PATH="/tmp/TESTS"


TESTED_PLATFORMS = ['linux', 'darwin']

def check_platform():
    return platform in TESTED_PLATFORMS



def check_main_directory(custom_path=None):
    if custom_path is not None:
       if not exists(custom_path):
           mkdir(custom_path)
    else:
        if not exists(DEFAULT_PATH):
            mkdir(DEFAULT_PATH)




#just returns a list of paths with concatenated handles.
#the handles are simple client names like client0, client1, etc
def get_client_storage_paths(testing_path, num_clients):
    paths = []
    for i in range(num_clients):
        new_handle = "client_{}".format(i)
        new_path = join(testing_path, new_handle + ".sqlite3")
        paths.append((new_path, new_handle))
    return paths

#we could make this faster by just swapping keys instead of adding
#one clients keys to another. That isn't really an issue since
#this is just for testing purposes and we won't be testing enough clients on a single machine for that
#to be a problem
def add_peer_info(local_handle, local_db, peer_handle, peer_db, peer_is_server):
    print("Adding {} keys to {} database".format(peer_handle, local_handle))
    local_ab = storage.AddressBook(local_handle, local_db)
    local_id = local_ab.fetch_id_by_username(local_handle)
    local_ks = storage.KeyStorage(local_id, local_db)

    peer_ab = storage.AddressBook(peer_handle, peer_db)
    peer_id = peer_ab.fetch_id_by_username(peer_handle)
    peer_ks = storage.KeyStorage(peer_id, peer_db)
    peer_identity_ed_bytes = peer_ks.fetch_by_type(peer_id, "ed")
    peer_identity_ed = crypto.get_private_ed_key_from_bytes(peer_identity_ed_bytes)
    peer_public_ed_bytes = crypto.get_ed_public_bytes(peer_identity_ed.public_key())

    peer_identity_dh_bytes = peer_ks.fetch_by_type(peer_id, "dh")
    peer_identity_dh = crypto.get_private_dh_key_from_bytes(peer_identity_dh_bytes)
    peer_public_dh_bytes = crypto.get_dh_public_bytes(peer_identity_dh.public_key())

    #insert into addressbook
    local_ab.add_contact(peer_id, peer_handle, peer_is_server)
    #insert into keystorage
    local_ks.insert_new_key(peer_id, peer_public_ed_bytes, peer_public_ed_bytes, "ed")
    local_ks.insert_new_key(peer_id, peer_public_dh_bytes, peer_public_dh_bytes, "dh")
    local_db.commit()


#creates a db for each client and the server and then swaps public keys
def populate_for_testing(testing_path, num_clients=3):
    client_paths = get_client_storage_paths(testing_path, num_clients)
    databases = {}
    for path,handle in client_paths:
        install.setup_database(handle, path)
        databases[handle] = storage.load_storage(path)
    server_handle = str(('127.0.0.1', 9080))
    server_path = join(testing_path, server_handle + ".sqlite3")
    install.setup_database(server_handle, server_path, server=True)
    databases[server_handle] = storage.load_storage(server_path)
    for local_handle, local_db in databases.items():
        for peer_handle, peer_db in databases.items():
            if peer_handle != local_handle:
                    add_peer_info(local_handle, local_db, peer_handle, peer_db, peer_handle == server_handle)





def setup_tests():
    system("rm /tmp/TESTS/*.sqlite3")
    testing_path = "/tmp/TESTS/"
    populate_for_testing(testing_path, 3)


def do_first_time_setup():
    if check_platform():
        check_main_directory()
        setup_tests()
    else:
        exit(-1)
