import os
import time
import utils
import struct
import messages
from clientui import load_client_information

SERVER_ADDRESS = ('127.0.0.1', 9080)
CLIENT_HANDLE_0 = "client_0"


def send_data(data):
    sock = utils.init_socket()
    sock.connect(SERVER_ADDRESS)
    sock.send(data)
    testsock = utils.init_socket()
    try:
        testsock.connect(SERVER_ADDRESS)
    except ConnectionError:
        print(data)
        exit(-1)

def fuzz_random(length):
    data = os.urandom(length)
    send_data(data)



def fuzz_packet_length(expected_length, real_length):
    fake_header = struct.pack("!BH", messages.TYPE_CLEAR, expected_length)
    fake_header += os.urandom(real_length)
    send_data(fake_header)

def fuzz_crypto_packet_length(expected_length, real_length):
    fake_header = struct.pack("!BH", messages.TYPE_CRYPTO, expected_length)
    fake_header += os.urandom(real_length)
    send_data(fake_header)

def fuzz_types():
    for i in range(0, 255):
        fake_header = struct.pack("!BH", i, 1)
        send_data(fake_header)

def fuzz_bad_sig():
    pass

def fuzz_unauthenticated():
    fuzz_random(1)
    fuzz_random(100)
    fuzz_random(10000)
    fuzz_types()
    fuzz_packet_length(0, 0)
    fuzz_packet_length(1, 100)
    fuzz_packet_length(100, 1)
    fuzz_packet_length(0, 100)
    fuzz_packet_length(100, 0)
    fuzz_packet_length(65535, 65535)
    print("Unauthenticated fuzzing done")



def fuzz_random_authenticated(testclient, length):
    data = os.urandom(length)
    testclient.sock.raw_send(data)

def get_authenticated_socket():
    testclient = load_client_information(CLIENT_HANDLE_0)
    testclient.connect_to_server(SERVER_ADDRESS)
    while not testclient.handshake_complete():
        testclient.update()
    return testclient



def fuzz_authenticated():
    testclient = get_authenticated_socket()
    for i in range(0, 65535 - 35):
        if testclient.sock.closed:
            testclient = get_authenticated_socket()
        fuzz_random_authenticated(testclient, i)
    print("Authenticated fuzzing done")




if __name__=="__main__":
    fuzz_unauthenticated()
    fuzz_authenticated()