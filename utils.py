import lzma
from base64 import b64encode, b64decode
from socket import socket, SOCK_STREAM, IPPROTO_TCP, AF_INET



def compress(byte_string):
    compressor = lzma.LZMACompressor()
    compressed_bytes = compressor.compress(byte_string)
    compressed_bytes += compressor.flush()
    return compressed_bytes

def decompress(byte_string):
    decompressor = lzma.LZMADecompressor()
    decompressed_bytes = decompressor.decompress(byte_string)
    return decompressed_bytes

def encode_64(byte_string):
    return b64encode(byte_string).decode()

def decode_64(encoded_string):
    return b64decode(encoded_string.encode())

def init_socket():
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)



