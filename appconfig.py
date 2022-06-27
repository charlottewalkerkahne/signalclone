import configparser
from os import getenv
from os.path import join

DEFAULT_APP_LOCATION = join("/tmp/TESTS/", ".gestureapp")
DEFAULT_STORAGE_NAME = "gestureappdb.sqlite"
DEFAULT_CONFIG_NAME = "gestureconfig"
DEFAULT_ATTACHMENT_DIR = join(DEFAULT_APP_LOCATION, "SAVED-ATTACHMENTS")

def flush_config(config_path, config):
    with open(config_path, 'w') as configfile:
        config.write(configfile)

def setup_config_file(config_path, username):
    config = configparser.ConfigParser()
    config['TESTING'] = {'Server-Address': "127.0.0.1",
                         'Server-Port': '9080',
                         'Login-Name': username}
    config['DEFAULTSECTION'] = {'section-name': 'TESTING'}
    flush_config(config_path, config)
    return config

def load_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

def change_default_config(config_path, new_default_section):
    config = load_config(config_path)
    config['DEFAULTSECTION'] = new_default_section


def load_server_config(config_path, servername):
    config = load_config(config_path)
    if servername in config:
        return config[servername]
    else:
        return None


def add_server(config_path, servername, address, port):
    config = load_config(config_path)
    if servername not in config:
        config[servername] = {
            'Server-Address': address,
            'Server-Port': port,
            'Login-Name': ""
        }
    flush_config(config_path, config)


def load_default_config():
    return setup_config_file(DEFAULT_APP_LOCATION, "")
    """
    config = configparser.ConfigParser()
    config_path = join(
        DEFAULT_APP_LOCATION,
        DEFAULT_CONFIG_NAME
    )
    config.read(config_path)
    return config
    """
