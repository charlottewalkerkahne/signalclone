import storage
import crypto
import appconfig
from os import getenv, mkdir
from os.path import join, exists, isdir



def create_keys():
    identity_ed = crypto.generate_ed_identity_key()
    identity_dh = crypto.generate_dh_identity_key()
    return identity_ed, identity_dh



def create_storage(db_path,server=False):
    return storage.create_storage(db_path, server)


def create_keystorage(db_connection):
    identity_ed, identity_dh = create_keys()
    identity_id = crypto.get_identity_id(identity_ed.public_key(), identity_dh.public_key())
    ks = storage.KeyStorage(
        identity_id,
        db_connection
    )

    identity_ed_bytes = crypto.get_ed_private_bytes(identity_ed)
    identity_ed_public_bytes = crypto.get_ed_public_bytes(identity_ed.public_key())
    ks.insert_new_key(identity_id, identity_ed_public_bytes, identity_ed_bytes, "ed")

    identity_dh_bytes = crypto.get_dh_private_bytes(identity_dh)
    identity_dh_public_bytes = crypto.get_dh_public_bytes(identity_dh.public_key())
    ks.insert_new_key(identity_id, identity_dh_public_bytes, identity_dh_bytes, "dh")
    return ks

def create_addressbook(username, identity_id, db_connection):
    ab = storage.AddressBook(username, db_connection)
    ab.add_contact(identity_id, username)
    return ab


def setup_application_root(application_root):
    if not exists(application_root):
        mkdir(application_root)
        return True
    else:
        if not isdir(application_root):
            print("Error: location exists but is not a directory.")
            return False
        return True


def setup_database(username, db_path, server=False):
    db_connection = create_storage(db_path, server)
    keystorage = create_keystorage(db_connection)

    addressbook = create_addressbook(username, keystorage.user_id, db_connection)
    #we don't setup sessionstorage or messagestorage in the initial creation
    db_connection.commit()
    db_connection.close()


def first_time_setup(username, app_root=appconfig.DEFAULT_APP_LOCATION, config_n=appconfig.DEFAULT_CONFIG_NAME, db_n=appconfig.DEFAULT_STORAGE_NAME,server=False):
    if setup_application_root(app_root):
        config_path = join(app_root, config_n)
        appconfig.setup_config_file(config_path, username)
        storage_path = join(app_root, db_n)
        setup_database(username, storage_path, server)
    else:
        exit(-1)

def get_username():
    getting_username = True
    while getting_username:
        username = input("Enter a username: ")
        if len(username) == 0:
            print("A username is required to continue the installation")
            print("Would you like to try again?")
        else:
            print("You entered: {}".format(username))
            dont_change = input("Change username (Y/n): ") == 'n'
            if dont_change:
                return username
    return None

def check_dependencies():
    pass

def load_key_from_disk():
    pass

def get_contact_info():
    getting_contact_info = True
    while getting_contact_info:
        peer_contactname = input("Name of new contact: ")
        print("You entered: {}".format(peer_contactname))
        dont_change = input("Change username (Y/n): ") == 'n'
        if dont_change:
            if len(peer_contactname) == 0:
                return None
            else:
                return peer_contactname

def get_peer_keys():
    getting_peer_keys = True
    while getting_peer_keys:
        peer_contactname = get_contact_info()
        if peer_contactname is None:
            return None


def cmdline_install():
    username = None
    peer_keys = None
    installing = True
    while installing:
        command_success = False
        username = get_username()
        if username is None:
            exit(-1)
        peer_keys = get_peer_keys()




