import os
import time
import utils
import struct
import messages
from clientui import load_client_information

SERVER_ADDRESS = ('127.0.0.1', 9080)
SERVER_ID = b'\xc5\xeb\x85\x0b\x88\xd2\xae6\x84V\xea-Z\xd8\xed\x10O\x9f\xee\r\xca\x05\xbb\xb3\xd1c\xf4\xb8\xaf\x9d\xe2['
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
    testclient = load_client_information(CLIENT_HANDLE_0)
    client_id = testclient.get_id_from_username(CLIENT_HANDLE_0)
    sock = utils.init_socket()
    sock.connect(SERVER_ADDRESS)
    invalid_sig = os.urandom(64)
    data = os.urandom(testclient.sock.buffer_packs[messages.TYPE_HELO].size)
    bad_sig_frame = struct.pack(messages.SIGNED_FRAME_HEADER_FORMAT,
                                messages.TYPE_SIGNED,
                                len(data),
                                client_id,
                                SERVER_ID,
                                0,
                                invalid_sig)
    bad_packet = struct.pack(messages.PACKET_HEADER_FORMAT, messages.TYPE_CLEAR, len(bad_sig_frame + data))
    sock.send(bad_packet + bad_sig_frame + data)

def fuzz_authentication_replay():
    pass

def fuzz_authentication():
    fuzz_bad_sig()
    fuzz_authentication_replay()

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
    fuzz_bad_sig()
    print("Unauthenticated fuzzing done")



#send random data of varying size after authenticating
def fuzz_random_authenticated():
    testclient = get_authenticated_socket()
    for i in range(0, 65535 - 35):
        if testclient.sock.closed:
            testclient = get_authenticated_socket()
        data = os.urandom(i)
        testclient.sock.raw_send(data)

def fuzz_authenticated_handshake():
    testclient = load_client_information(CLIENT_HANDLE_0)
    testclient.connect_to_server(SERVER_ADDRESS)


def get_authenticated_socket():
    testclient = load_client_information(CLIENT_HANDLE_0)
    testclient.connect_to_server(SERVER_ADDRESS)
    while not testclient.handshake_complete():
        testclient.update()
    return testclient



def fuzz_authenticated():
    #fuzz_random_authenticated()
    fuzz_authenticated_handshake()
    print("Authenticated fuzzing done")




if __name__=="__main__":
    fuzz_unauthenticated()
    #fuzz_authenticated()