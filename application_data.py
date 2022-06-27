import json
import utils

TYPE_DM = 0x0
TYPE_INFO_REQUEST = 0x1
TYPE_INFO_RESPONSE = 0x2
TYPE_DM_CONTROL = 0x3
TYPE_BROADCAST = 0x4

DM_CONTROL_NEW_CONVO = 0x5
DM_CONTROL_ADD_RECIPIENTS = 0x6

REQUEST_ACTIVE_USERS = 0x0



"""
HEADER:
    {
        MESSAGE_TYPE: type (unsigned char)
        SOURCE_ID: source_id (base16 encoding of id)
        PADDING: padding_string (a string used for padding to mitigate traffic correlation) (UNIMPLEMENTED)
    }



TYPE_DM_BODY:
    {
        CONVO_ID: conversation_id (a 44 byte identifier for a conversation)
        timestamp int representing the timestamp
        CONTENT: content    (string)
        ATTACHMENT: attachment (bool. If yes, then content gets saved to file)
    }

TYPE_INFO_REQUEST:
    {
        REQUEST_TYPE: request_type (unsigned char)
    }

TYPE_INFO_RESPONSE:
    {
        RESPONSE_TYPE: request_type (unsigned char)
        RESPONSE_CONTENT: data (string)
    }

TYPE_BROADCAST:
    {
        CONTENT: string
    }

TYPE_DM_CONTROL:
    {
        SALT: used to hash with the participant ids conversation_id (a 32 byte identifier for a conversation)
        CONTROL_TYPE: DM_CONTROL_TYPE (unsigned char)
        CONTROL_CONTENT: (list of strings)
    }

TYPE_APP_UPDATE:
    {
        UPDATE_TYPE: type (unsigned char)
        UPDATE_CONTENT: (string)
    }

"""

TYPE_DM = 0
TYPE_INFO_REQUEST = 1
TYPE_INFO_RESPONSE = 2
TYPE_DM_CONTROL = 3
TYPE_BROADCAST = 4
TYPE_APP_UPDATE = 5

REQUEST_ACTIVE_USERS = 6
REQUEST_UNDELIVERED_MESSAGES = 7
ACK_FETCHED_MESSAGES = 8



#TODO GET THIS FOR REAL
PAD_LENGTH = 0

def encode_header(source_id, header_type, length):
    source_id = utils.encode_64(source_id)
    pad_length = (PAD_LENGTH-length)
    padding=''
    if pad_length > 0:
        padding += 'A' * pad_length
    header = [{'MESSAGE_TYPE':header_type, 'SOURCE_ID':source_id, 'PADDING':padding}]
    return header

def encode_dm(source_id, convo_id, msg_num, attachment, content):
    convo_id = utils.encode_64(convo_id)
    length = len(content) + 64 + 64 + len(str(msg_num))
    msg_header = encode_header(source_id, TYPE_DM, length)
    msg_body = {'CONVERSATION_ID':convo_id, 'CONTENT':content, 'ATTACHMENT':attachment, "TIMESTAMP": msg_num}
    msg_header.append(msg_body)
    encoded = json.dumps(msg_header)
    return encoded

def encode_info_request(source_id, request_type):
    length = 65
    msg_header = encode_header(source_id, TYPE_INFO_REQUEST, length)
    msg_body = {'REQUEST_TYPE':request_type}
    msg_header.append(msg_body)
    return json.dumps(msg_header)

def encode_info_response(source_id, request_type, content):
    length = len(content) + 65
    msg_header = encode_header(source_id, TYPE_INFO_RESPONSE, length)
    msg_body = {'RESPONSE_TYPE':request_type, 'RESPONSE_CONTENT':content}
    msg_header.append(msg_body)
    return json.dumps(msg_header)

def encode_dm_control(source_id, control_type, control_content, salt):
    salt = utils.encode_64(salt)
    length = (len(control_content) * 44) + 44 + 65
    msg_header = encode_header(source_id, TYPE_DM_CONTROL, length)
    if control_type == DM_CONTROL_NEW_CONVO:
        control_content = list(map(lambda i: utils.encode_64(i), control_content))
    msg_body = {'SALT':salt, 'CONTROL_TYPE':control_type, 'CONTENT':control_content}
    msg_header.append(msg_body)
    return json.dumps(msg_header)

def encode_broadcast(source_id, content):
    length = len(content) + 64
    msg_header = encode_header(source_id, TYPE_BROADCAST, length)
    msg_body = {'CONTENT':content}
    msg_header.append(msg_body)
    return json.dumps(msg_header)



def is_valid_header(header):
    if type(header) == type({}):
        if 'MESSAGE_TYPE' not in header:
            return False
        elif 'SOURCE_ID' not in header:
            return False
        elif 'PADDING' not in header:
            return False
        else:
            return True
    else:
        return False

def is_valid_dm(body):
    if 'CONVERSATION_ID' not in body:
        return False
    if 'CONTENT' not in body:
        return False
    if 'TIMESTAMP' not in body:
        return False
    if 'ATTACHMENT' not in body:
        return False
    return True

def valid_dm_control_content(content, control_type):
    if control_type == DM_CONTROL_NEW_CONVO:
        if type(content) != type([]):
            #print("Expected a list")
            return False
        for each in content:
            if type(each) != type(""):
                #print("expected a string")
                return False
        #print("dm control is valid")
        return True
    else:
        #print("Have not implemented control type {}".format(control_type))
        return False

def is_valid_dm_control(body):
    if 'SALT' not in body:
        return False
    if 'CONTROL_TYPE' not in body:
        return False
    if 'CONTENT' not in body:
        return False
    return valid_dm_control_content(body['CONTENT'], body['CONTROL_TYPE'])

def is_valid_broadcast(body):
    if 'CONTENT' not in body:
        return False
    return True

def is_valid_info_request(body):
    if 'REQUEST_TYPE' not in body:
        return False
    return True

def is_valid_info_response(body):
    if 'RESPONSE_TYPE' not in body:
        return False
    if 'RESPONSE_CONTENT' not in body:
        return False
    return True


def is_valid_body(body, message_type):
    if type(body) == type({}):
        if message_type == TYPE_DM:
            return is_valid_dm(body)
        elif message_type == TYPE_DM_CONTROL:
            return is_valid_dm_control(body)
        elif message_type == TYPE_BROADCAST:
            return is_valid_broadcast(body)
        elif message_type == TYPE_INFO_REQUEST:
            return is_valid_info_request(body)
        elif message_type == TYPE_INFO_RESPONSE:
            return is_valid_info_response(body)
        else:
            return False
    else:
        return False


#there needs to be some kind of safe version of this
def decode_data(encoded_data):
    decoded_data = None
    try:
        decoded_data = json.loads(encoded_data)
    except json.decoder.JSONDecodeError:
        print("json decoding error")
        return None
    if len(decoded_data) != 2:
        return None
    if is_valid_header(decoded_data[0]):
        header = decoded_data[0]
        body = decoded_data[1]
        if is_valid_body(body, header['MESSAGE_TYPE']):
            return [header, body]
        else:
            return None
    elif is_valid_header(decoded_data[1]):
        header = decoded_data[1]
        body = decoded_data[0]
        if is_valid_body(body, header['MESSAGE_TYPE']):
            return [header,body]
        else:
            return None
    else:
        return None
