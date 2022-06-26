import crypto
from struct import pack, unpack



ID_FORMAT = "32s"
SIGNATURE_FORMAT = "64s"
SALT_FORMAT = "32s"
DH_FORMAT = "32s"
UNSIGNED_CHAR = "B"
UNSIGNED_SHORT = "H"
UNSIGNED_INT = "I"

FRAME_TYPE_FORMAT = "!B"

PACKED_DH_INFO = "96s"

FRAME_ID_FORMAT = "32s"

RATCHET_HEADER_FORMAT = "!" + DH_FORMAT + UNSIGNED_INT + UNSIGNED_INT

PACKET_HEADER_FORMAT = "!" + UNSIGNED_CHAR + UNSIGNED_SHORT
CRYPTO_HEADER_FORMAT = "!" + UNSIGNED_CHAR + UNSIGNED_SHORT + ID_FORMAT

#type, length, source, dest, frame_id
FRAME_HEADER_FORMAT = "!" + UNSIGNED_CHAR + UNSIGNED_INT + ID_FORMAT + ID_FORMAT + UNSIGNED_INT

#type, length, source, dest, frame_id, signature
SIGNED_FRAME_HEADER_FORMAT = FRAME_HEADER_FORMAT + SIGNATURE_FORMAT

#type, length, source, dest, frame_id, dh_info
HANDSHAKE_FRAME_FORMAT = FRAME_HEADER_FORMAT + PACKED_DH_INFO

#type, length, source, dest, frame_id, spk, sig
PREKEY_BUNDLE_RESPONSE_FORMAT = FRAME_HEADER_FORMAT + ID_FORMAT + DH_FORMAT + SIGNATURE_FORMAT

#type, length, source, dest, frame_id, spk, sig
PREKEY_BUNDLE_POST_FORMAT = FRAME_HEADER_FORMAT  + DH_FORMAT + SIGNATURE_FORMAT

#type, length, source, dest, frame_id, target_id
PREKEY_BUNDLE_REQUEST_FORMAT = FRAME_HEADER_FORMAT +  ID_FORMAT

#type, length, source, dest, frame_id, spk, otk, ek, salt
ASYNC_FRAME_FORMAT = FRAME_HEADER_FORMAT +  DH_FORMAT + DH_FORMAT + DH_FORMAT + SALT_FORMAT

#type, length, source, dest, frame_id, ratchet_header
RATCHET_FRAME_FORMAT = FRAME_HEADER_FORMAT +  "40s"

#type, length, source, dest, frame_id, frame_type, stream_type, stream_id
STREAM_FORMAT = FRAME_HEADER_FORMAT + UNSIGNED_CHAR + ID_FORMAT

#type, length, source, dest, frame_type
DATA_FRAME_FORMAT = FRAME_HEADER_FORMAT

#type, length, source, dest, frame_id, broadcast_id, group_key_and_hash
GROUP_KEY_FRAME = FRAME_HEADER_FORMAT +  ID_FORMAT + "64s"
#broadcast first sent to server. Server then sends the frame to each client id in the body of the
#frame

#frame_type, length, source_id, dest_id, frame_id(sending), error_code, frame_id(of the bad frame), offset
ERROR_FRAME_FORMAT = FRAME_HEADER_FORMAT + UNSIGNED_CHAR + UNSIGNED_INT


OKAY_FRAME = FRAME_TYPE_FORMAT

#type, length, source, dest, frame_id, broadcast_id, num_recipients
BROADCAST_REQUEST = FRAME_HEADER_FORMAT + ID_FORMAT + UNSIGNED_SHORT

#type, length, source, dest, frame_id, broadcast_id
BROADCAST_FORMAT = FRAME_HEADER_FORMAT + ID_FORMAT

TYPE_HELO = 0
TYPE_HELO_RESPONSE = 1
TYPE_ERROR = 2
TYPE_DATA = 3
TYPE_SHUTDOWN_WAIT = 4
TYPE_SHUTDOWN_NOWAIT = 5
TYPE_OKAY = 6
TYPE_STREAM = 7

#Error codes
CRYPTO_ERROR_UNKNOWN_SESSION_ID = 8
SIGNED_ERROR_BAD_SIGNATURE = 9
CRYPTO_ERROR_DECRYPTION_FAILURE = 10
BAD_ADDRESS = 11
PREKEY_ERROR_NO_KEYS_FOUND = 12
UNEXPECTED_FRAME = 13
DESERIALIZATION_ERROR = 14
UNAUTHORIZED_PEER = 15
HANDSHAKE_ERROR = 16
KEY_INSERTION_ERROR = 17
UNKNOWN_FRAMETYPE = 18
BAD_STREAM = 19
LENGTH_ERROR = 20


ASYNC_FRAME = 13

TYPE_RATCHET_HELO = 14
TYPE_RATCHET_HELO_RESPONSE = 15
TYPE_PREKEY_BUNDLE_RESPONSE = 16

TYPE_RATCHET_FRAME = 17


TYPE_CLEAR = 18
TYPE_SIGNED = 19
TYPE_CRYPTO = 20

PREKEY_BUNDLE_POST = 21
PREKEY_BUNDLE_REQUEST = 22
OTK_FRAME = 23
IDENTITY_KEY_FRAME = 24

MESSAGE_FETCH_REQUEST = 25

TYPE_BROADCAST = 26
TYPE_GROUP_KEY = 27
TYPE_BROADCAST_REQUEST = 28


STREAM_OPEN = 0x0
STREAM_CONTINUE = 0x1
STREAM_CLOSE = 0x2

MAX_APPLICATION_LENGTH = 4000 #for testing

#will ack each frame with frame_id up to offset
#frame_type frame_id offset
EXPECTED_ORDER = {
    TYPE_CLEAR: [TYPE_SIGNED],
    TYPE_CRYPTO: [PREKEY_BUNDLE_POST, PREKEY_BUNDLE_REQUEST, TYPE_PREKEY_BUNDLE_RESPONSE, ASYNC_FRAME, TYPE_RATCHET_FRAME, TYPE_ERROR, TYPE_BROADCAST, TYPE_BROADCAST_REQUEST, TYPE_GROUP_KEY],
    TYPE_SIGNED: [TYPE_HELO, TYPE_HELO_RESPONSE],
    TYPE_HELO: [],
    TYPE_HELO_RESPONSE: [],
    PREKEY_BUNDLE_POST: [],
    PREKEY_BUNDLE_REQUEST: [],
    TYPE_PREKEY_BUNDLE_RESPONSE: [],
    ASYNC_FRAME: [TYPE_RATCHET_FRAME],
    TYPE_RATCHET_FRAME: [TYPE_ERROR, TYPE_DATA, TYPE_GROUP_KEY, TYPE_STREAM],
    TYPE_ERROR: [],
    TYPE_BROADCAST_REQUEST: [],
    TYPE_BROADCAST: [],
    TYPE_GROUP_KEY: [],
    TYPE_STREAM: [TYPE_DATA],
    TYPE_DATA: []
}


class RatchetHeader:
    def __init__(self, dh, pn, ns):
        self.dh = dh
        self.pn = pn
        self.ns = ns
        self.header_bytes = None
    @classmethod
    def from_bytes(cls, raw_bytes):
        if len(raw_bytes) != 40: #32 + 4 + 4
            return None
        dh,pn,ns = unpack("!32sII", raw_bytes)
        new_header = RatchetHeader(dh, pn, ns)
        new_header.header_bytes = raw_bytes
        return new_header
    def to_bytes(self):
        local_pub_bytes = crypto.get_dh_public_bytes(self.dh)
        return pack("!32sII", local_pub_bytes, self.pn, self.ns)
