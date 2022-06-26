import os
import crypto
import struct
import messages
from socket import selectors
from multiprocessing import Queue
from struct import pack, unpack, error
DEFAULT_TIMEOUT = .1

#setdefaulttimeout(DEFAULT_TIMEOUT)

class SecureSock:
    def __init__(self, sock, keyring):
        self.sock = sock
        self.sock.setblocking(False)
        self.keyring = keyring
        self.connection_id = None
        self.application_frames = Queue()
        self.incomplete_frames = {} #peer_id: {stream_id: [frames]}
        self.secured = False
        self.shutting_down = False
        self.closed = False
        self.log_queue = Queue()
        self.sock_poll = selectors.select.poll()
        self.sock_poll.register(self.sock)
        self.pending_encryption = {} #peer_id: frame_list
        self.pending_group_messages = {} #broadcast_id: {source_id: source_id_bytes, key_and_hash: key_and_hash bytes, ciphertext: ciphertext bytes}
        self.unacked_frames = {} #frame_id: [list_of_frame_bytes]
        self.current_frame_id = struct.unpack("!H", os.urandom(2))[0] #gen starting frame_id


        self.buffer_packs = {} #frame_type: struct.Struct(frame_type format string)
        self.buffer_packs[messages.TYPE_CLEAR] = struct.Struct(messages.PACKET_HEADER_FORMAT)
        self.buffer_packs[messages.TYPE_CRYPTO] = struct.Struct(messages.CRYPTO_HEADER_FORMAT)
        self.buffer_packs[messages.TYPE_SIGNED] = struct.Struct(messages.SIGNED_FRAME_HEADER_FORMAT)
        self.buffer_packs[messages.TYPE_DATA] = struct.Struct(messages.DATA_FRAME_FORMAT)
        self.buffer_packs[messages.TYPE_HELO] = struct.Struct(messages.HANDSHAKE_FRAME_FORMAT)
        self.buffer_packs[messages.TYPE_HELO_RESPONSE] = struct.Struct(messages.HANDSHAKE_FRAME_FORMAT)
        self.buffer_packs[messages.TYPE_STREAM] = struct.Struct(messages.STREAM_FORMAT)
        self.buffer_packs[messages.PREKEY_BUNDLE_REQUEST] = struct.Struct(messages.PREKEY_BUNDLE_REQUEST_FORMAT)
        self.buffer_packs[messages.TYPE_PREKEY_BUNDLE_RESPONSE] = struct.Struct(messages.PREKEY_BUNDLE_RESPONSE_FORMAT)
        self.buffer_packs[messages.PREKEY_BUNDLE_POST] = struct.Struct(messages.PREKEY_BUNDLE_POST_FORMAT)
        self.buffer_packs[messages.ASYNC_FRAME] = struct.Struct(messages.ASYNC_FRAME_FORMAT)
        self.buffer_packs[messages.TYPE_RATCHET_FRAME] = struct.Struct(messages.RATCHET_FRAME_FORMAT)
        self.buffer_packs[messages.TYPE_BROADCAST] = struct.Struct(messages.BROADCAST_FORMAT)
        self.buffer_packs[messages.TYPE_BROADCAST_REQUEST] = struct.Struct(messages.BROADCAST_REQUEST)
        self.buffer_packs[messages.TYPE_GROUP_KEY] = struct.Struct(messages.GROUP_KEY_FRAME)
        self.buffer_packs[messages.TYPE_ERROR] = struct.Struct(messages.ERROR_FRAME_FORMAT)
    def connect(self, peer_addr, peer_id):
        self.sock.setblocking(True)
        self.sock.connect(peer_addr)
        self.sock.setblocking(False)
        self.send_handshake_request(peer_id)
        self.connection_id = peer_id
    def sock_is_ready(self):
        return self.sock_poll.poll(.1)
    def channel_secured(self, peer_id):
        return peer_id in self.keyring.active_sessions
    def shutdown(self):
        self.sock.close()
        self.keyring.remove_synchronous_session(self.connection_id)
        self.keyring.keystorage.sync()
        del self.keyring
    def update(self):
        if self.closed:
            self.shutdown()
        else:
            self.raw_recv()
    def read(self):
        if not self.shutting_down:
            if not self.application_frames.empty():
                return self.application_frames.get()
            else:
                return None
        return None
    def write(self, application_frame, dest_id):
        #accepts a frame object returns a status so the application
        #knows if it was sent successfully
        return self.send_application_data(dest_id, application_frame)
    def raw_recv(self):
        raw_header = None
        packet = None
        packet_received = False
        try:
            raw_header = self.sock.recv(3)
            packet_type, length = unpack("!BH", raw_header)
            if packet_type == messages.TYPE_CRYPTO:
                length += 32
            packet = self.sock.recv(length)
            packet_received = True
        except ConnectionResetError:
            self.closed = True
            self.shutdown()
        except error:
            self.closed = True
            self.shutdown()
        except BlockingIOError:
            assert(raw_header == None)
            assert(packet == None)
            socktimeout = True
        if packet_received:
            real_length = len(packet)
            assert(real_length <= length and "Got bad packet length")
            while real_length < length: #TODO MAKE SURE THIS DOESNT HANG
                packet += self.sock.recv(length-real_length)
                real_length += len(packet)
            raw_packet = raw_header + packet
            self.process_packet(packet_type, raw_packet, real_length)
    def raw_send(self, frame_bytes):
        assert(type(frame_bytes) == type(b"\x00"))
        packet_bytes = None
        length = None
        if self.secured:
            session_id = self.keyring.active_sessions[self.connection_id][0]
            assert(session_id is not None)
            encrypted_body = self.keyring.session_encrypt(session_id, frame_bytes)
            crypto_struct = self.buffer_packs[messages.TYPE_CRYPTO]
            packet = crypto_struct.pack(
                messages.TYPE_CRYPTO,
                len(encrypted_body),
                session_id
            )
            packet_bytes = packet + encrypted_body
            length = len(packet_bytes)
        else:
            clear_struct = self.buffer_packs[messages.TYPE_CLEAR]
            packet = clear_struct.pack(
                messages.TYPE_CLEAR,
                len(frame_bytes)
            )
            packet_bytes = packet + frame_bytes
            length = len(packet_bytes)
        if packet_bytes is not None:
            sent = False
            offset = 0
            bytes_sent = 0
            while not sent:
                sock_status = self.sock_is_ready()
                if len(sock_status) == 1: #otherwise busy
                    while bytes_sent < length:
                        bytes_sent += self.sock.send(packet_bytes[offset:])
                        offset += bytes_sent
                    sent = True
                else:
                    pass
        else:
            return None
    def process_packet(self, packet_type, raw_packet, packet_length):
        if packet_type not in self.buffer_packs:
            return None
        buf_pack = self.buffer_packs[packet_type]
        if packet_length < buf_pack.size:
            return None
        packet_header = buf_pack.unpack(raw_packet[:buf_pack.size])
        packet_body = raw_packet[buf_pack.size:]
        if packet_type == messages.TYPE_CRYPTO:
            session_id = packet_header[2]
            packet_body = self.keyring.session_decrypt(session_id, packet_body)
            if packet_body is None:
                #TODO send decryption error
                pass
            else:
                self.process_crypto_packet(packet_body, len(packet_body))
        elif packet_type == messages.TYPE_CLEAR:
             self.process_clear_packet(packet_body, len(packet_body))
    def process_clear_packet(self, packet_body, length):
        frame_type = struct.unpack("!B", packet_body[:1])[0]
        if frame_type not in self.buffer_packs:
            #TODO send unrecognized frame error
            pass
        else:
            if frame_type != messages.TYPE_SIGNED:
                #TODO send unexpected frame error
                pass
            else:
                err_info = self.process_frame(frame_type, packet_body, length)
                if err_info is not None:
                    self.send_error_frame(err_info[0], err_info[1])
    def process_crypto_packet(self, packet_body, length):
        frame_type = struct.unpack("!B", packet_body[:1])[0]
        if frame_type not in self.buffer_packs:
            #TODO send unrecognized error frame
            pass
        else:
            err_info = self.process_frame(frame_type, packet_body, length)
            if err_info is not None:
                self.send_error_frame(err_info[0], err_info[1])
    def process_frame(self, frame_type, frame_bytes, real_length):
        if frame_type not in self.buffer_packs:
            return messages.UNKNOWN_FRAMETYPE
        frame_struct = self.buffer_packs[frame_type]
        if real_length < frame_struct.size:
            return messages.LENGTH_ERROR
        frame_header = frame_struct.unpack(frame_bytes[:frame_struct.size])
        if frame_header[3] != self.keyring.identity_id:
            self.application_frames.put((frame_bytes, frame_header[2], frame_header[3]))
            return None
        expected_length = frame_header[1]
        if real_length - frame_struct.size != expected_length:
            return messages.LENGTH_ERROR
        frame_body = frame_bytes[frame_struct.size:]
        if frame_type == messages.TYPE_HELO:
            err = self.process_handshake_request(frame_header)
        elif frame_type == messages.TYPE_HELO_RESPONSE:
            err = self.process_handshake_response(frame_header)
        elif frame_type == messages.TYPE_ERROR:
            err = self.process_error(frame_header)
        elif frame_type == messages.TYPE_BROADCAST:
            err = self.process_broadcast_message(frame_header, frame_body)
        elif frame_type == messages.TYPE_SIGNED:
            err = self.process_signed_frame(frame_header, frame_body)
        elif frame_type == messages.TYPE_RATCHET_FRAME:
            err = self.process_ratchet_frame(frame_header, frame_body)
        elif frame_type == messages.ASYNC_FRAME:
            err = self.process_async_frame(frame_header, frame_body)
        elif frame_type == messages.TYPE_DATA:
            err = self.process_data_frame(frame_header, frame_body)
        elif frame_type == messages.TYPE_PREKEY_BUNDLE_RESPONSE:
            err = self.process_prekey_bundle_response(frame_header, frame_body)
        elif frame_type == messages.PREKEY_BUNDLE_POST:
            err = self.process_prekey_bundle_post(frame_header, frame_body)
        elif frame_type == messages.PREKEY_BUNDLE_REQUEST:
            err = self.process_prekey_bundle_request(frame_header)
        elif frame_type == messages.TYPE_GROUP_KEY:
            err = self.process_group_key_frame(frame_header)
        elif frame_type == messages.TYPE_BROADCAST_REQUEST:
            err = self.process_broadcast_request(frame_header, frame_body)
        elif frame_type == messages.TYPE_STREAM:
            err = self.process_stream_frame(frame_header, frame_body)
        if err is not None:
            return err, frame_header
        else:
            return None
    def process_stream_frame(self, frame_header, frame_body):
        frame_type, length, source, dest, frame_id, stream_type, stream_id = frame_header
        if stream_type == messages.STREAM_OPEN:
            if source in self.incomplete_frames:
                source_incomplete_streams = self.incomplete_frames[source]
                source_incomplete_streams[stream_id] = [frame_body]
            else:
                self.incomplete_frames[source] = {stream_id:[frame_body]}
        elif stream_type == messages.STREAM_CONTINUE:
            if source in self.incomplete_frames:
                source_incomplete_streams = self.incomplete_frames[source]
                source_incomplete_streams[stream_id].append(frame_body)
            else:
                return messages.BAD_STREAM
        elif stream_type == messages.STREAM_CLOSE:
            if source in self.incomplete_frames:
                source_incomplete_streams = self.incomplete_frames[source]
                complete_frame = source_incomplete_streams[stream_id]
                complete_frame.append(frame_body)
                del self.incomplete_frames[source][stream_id]
                return self.process_complete_stream(complete_frame)
            else:
                return messages.BAD_STREAM
    def process_complete_stream(self, complete_stream):
        assert(len(complete_stream) > 0)
        frame_bytes = b"".join(complete_stream)
        frame_type = struct.unpack("!B", frame_bytes[:1])[0]
        frame_length = len(frame_bytes)
        if frame_type != messages.TYPE_RATCHET_FRAME:
            return messages.UNEXPECTED_FRAME
        else:
            return self.process_frame(frame_type, frame_bytes, frame_length)
    def process_data_frame(self, frame_header, frame_body):
        frame_type, length, source, dest, frame_id = frame_header
        self.application_frames.put((frame_body, source, dest))
        return None
    def process_error(self, frame_header):
        frame_type, length, source, dest, frame_id, error_code, error_id = frame_header
        if error_code == messages.CRYPTO_ERROR_UNKNOWN_SESSION_ID:
            if source in self.keyring.active_sessions:
                #reset the session the next time something is sent
                del self.keyring.active_sessions[source]
        elif error_code == messages.SIGNED_ERROR_BAD_SIGNATURE:
            pass
        elif error_code == messages.CRYPTO_ERROR_DECRYPTION_FAILURE:
            if source in self.keyring.active_sessions:
                # reset the session the next time something is sent
                del self.keyring.active_sessions[source]
        elif error_code == messages.BAD_ADDRESS:
            pass
        elif error_code == messages.PREKEY_ERROR_NO_KEYS_FOUND:
            pass
    def process_shutdown(self, frame_header, frame_body):
        self.shutdown_sock()
    def process_okay(self, source_id, dest_id, length, frame_header):
        pass
    def process_signed_frame(self, frame_header, frame_body):
        frame_type, expected_length, source, dest, frame_id, signature = frame_header
        signing_pub_key = self.keyring.peer_identity_ed_keys[source]
        if signing_pub_key is not None:
            if crypto.verify(signing_pub_key, signature, frame_body):
                body_type = struct.unpack("!B", frame_body[:1])[0]
                return self.process_frame(body_type, frame_body, len(frame_body))
            else:
                return messages.SIGNED_ERROR_BAD_SIGNATURE
        else:
            return messages.UNAUTHORIZED_PEER
    def process_handshake_request(self, frame_header):
        frame_type, length, source, dest, frame_id, dh_info = frame_header
        peer_salt, peer_dh_s, peer_dh_r = crypto.get_unpacked_dh_public_key(dh_info)
        peer_id = self.keyring.update_synchronous_session(source, peer_salt, peer_dh_r, peer_dh_s)
        if peer_id is not None:
            self.send_handshake_response(source)
            self.keyring.wrap_synchronous_session(source)
            self.secured = True
            self.connection_id = source
        else:
            return messages.HANDSHAKE_ERROR
    def process_handshake_response(self, frame_header):
        frame_type, length, source, dest, frame_id, dh_info = frame_header
        peer_salt,peer_dh_s,peer_dh_r = crypto.get_unpacked_dh_public_key(dh_info)
        peer_id = self.keyring.update_synchronous_session(source, peer_salt, peer_dh_r, peer_dh_s)
        if peer_id is not None:
            self.keyring.wrap_synchronous_session(peer_id)
            self.secured = True
            self.connection_id = peer_id
        else:
            return messages.HANDSHAKE_ERROR
    def process_prekey_bundle_response(self, frame_header, frame_body):
        frame_type, length, source, dest, frame_id, signing_client_id, spk, sig = frame_header
        if self.keyring.add_public_spk(signing_client_id, spk, sig): #verified and added
            otk_list = crypto.get_unpacked_otk_list(frame_body)
            if otk_list is not None:
                for otk in otk_list:
                    self.keyring.add_public_otk(signing_client_id, otk)
            else:
                return messages.KEY_INSERTION_ERROR
            if signing_client_id in self.pending_encryption:
                unsent_list = self.pending_encryption[signing_client_id]
                for unsent_frame in unsent_list:
                    if signing_client_id in self.keyring.active_sessions:
                        session_id = self.keyring.active_sessions[signing_client_id]
                        self.send_ratchet_frame(unsent_frame, signing_client_id, session_id)
                    else:
                        self.send_async_frame(unsent_frame, signing_client_id)
        else:
            return messages.KEY_INSERTION_ERROR
    def process_prekey_bundle_post(self, frame_header, frame_body):
        frame_type, length, source, dest, frame_id, spk, sig = frame_header
        if self.keyring.add_public_spk(source, spk, sig):
            otk_list = crypto.get_unpacked_otk_list(frame_body)
            if otk_list is not None:
                for otk in otk_list:
                    self.keyring.add_public_otk(source, otk)
            else:
                return messages.KEY_INSERTION_ERROR
        else:
            return messages.KEY_INSERTION_ERROR
    def process_prekey_bundle_request(self, frame_header, otk_count=10):
        frame_type, length, source, dest, frame_id, target_id = frame_header
        otk_list = []
        for i in range(0, otk_count):
            otk = self.keyring.fetch_public_otk(target_id)
            if otk is None:
                break
            else:
                otk_list.append(otk)
        if len(otk_list) == 0:
            return messages.PREKEY_ERROR_NO_KEYS_FOUND
        spk_and_sig = self.keyring.fetch_public_spk(target_id)
        if spk_and_sig is None:
            return messages.PREKEY_ERROR_NO_KEYS_FOUND
        self.send_prekey_bundle_response(target_id, spk_and_sig, otk_list)
    def send_prekey_bundle_response(self, target_id, spk_and_sig, otk_list):
        prekey_response_struct = self.buffer_packs[messages.TYPE_PREKEY_BUNDLE_RESPONSE]
        spk = spk_and_sig[:32]
        sig = spk_and_sig[32:]
        packed_otk_list = crypto.get_packed_otk_list(otk_list)
        assert(self.connection_id is not None)
        prekey_response_frame = prekey_response_struct.pack(
            messages.TYPE_PREKEY_BUNDLE_RESPONSE,
            len(packed_otk_list),
            self.keyring.identity_id,
            self.connection_id,
            self.current_frame_id,
            target_id,
            spk,
            sig
        )
        self.raw_send(prekey_response_frame + packed_otk_list)
    def send_prekey_bundle_post(self, otk_count):
        spk_and_sig = self.keyring.fetch_public_spk(self.keyring.identity_id)
        if spk_and_sig is None:
            spk_and_sig = self.keyring.gen_spk()
        spk = spk_and_sig[:32]
        sig = spk_and_sig[32:]
        otk_list = []
        for i in range(0, otk_count):
            otk_list.append(self.keyring.gen_otk())
        packed_list = crypto.get_packed_otk_list(otk_list)

        prekey_post_struct = self.buffer_packs[messages.PREKEY_BUNDLE_POST]
        prekey_frame = prekey_post_struct.pack(
            messages.PREKEY_BUNDLE_POST,
            len(packed_list),
            self.keyring.identity_id,
            self.connection_id,
            self.current_frame_id,
            spk,
            sig
        )
        return self.raw_send(prekey_frame + packed_list)
    def send_prekey_bundle_request(self, target_id):
        prekey_request_struct = self.buffer_packs[messages.PREKEY_BUNDLE_REQUEST]
        frame_bytes = prekey_request_struct.pack(
            messages.PREKEY_BUNDLE_REQUEST,
            0,
            self.keyring.identity_id,
            self.connection_id,
            self.current_frame_id,
            target_id
        )
        return self.raw_send(frame_bytes)
    def send_handshake_request(self, dest):
        self.keyring.create_new_synchronous_session(dest)
        salt = self.keyring.incomplete_session_keys[dest]["enc"]["salt"]
        dh_r = self.keyring.incomplete_session_keys[dest]["dec"]["l_dh"].public_key()
        dh_s = self.keyring.incomplete_session_keys[dest]["enc"]["l_dh"].public_key()
        packed_dh_info = crypto.get_packed_dh_public_key(salt, dh_s, dh_r)
        handshake_request_struct = self.buffer_packs[messages.TYPE_HELO]
        frame = handshake_request_struct.pack(
            messages.TYPE_HELO,
            0,
            self.keyring.identity_id,
            dest,
            self.current_frame_id,
            packed_dh_info
        )
        return self.send_signed_frame(frame, dest)
    def send_signed_frame(self, frame_body, dest):
        length = len(frame_body)
        sig = crypto.sign(
            self.keyring.identity_ed_key,
            frame_body
        )
        sig_struct = self.buffer_packs[messages.TYPE_SIGNED]
        frame = sig_struct.pack(
            messages.TYPE_SIGNED,
            length,
            self.keyring.identity_id,
            dest,
            self.current_frame_id,
            sig
        )
        return self.raw_send(frame + frame_body)
    def send_handshake_response(self, dest):
        source_id = self.keyring.identity_id
        salt = self.keyring.incomplete_session_keys[dest]["enc"]["salt"]
        dh_r = self.keyring.incomplete_session_keys[dest]["dec"]["l_dh"].public_key()
        dh_s = self.keyring.incomplete_session_keys[dest]["enc"]["l_dh"].public_key()
        packed_dh_info = crypto.get_packed_dh_public_key(salt, dh_s, dh_r)
        handshake_response_struct = self.buffer_packs[messages.TYPE_HELO_RESPONSE]
        frame = handshake_response_struct.pack(
            messages.TYPE_HELO_RESPONSE,
            0,
            self.keyring.identity_id,
            dest,
            self.current_frame_id,
            packed_dh_info
        )
        return self.send_signed_frame(frame, dest)
    def send_error_frame(self, err_code, frame_header):
        frame = self.buffer_packs[messages.TYPE_ERROR].pack(
            messages.TYPE_ERROR,
            0,
            self.keyring.identity_id,
            frame_header[3],
            self.current_frame_id,
            err_code,
            frame_header[4]
        )
        self.raw_send(frame)
    def send_unreachable_frame(self, dest_id):
        pass
    def process_shutdown_frame(self, frame_header, frame_body):
        self.shutdown_sock()
    def send_shutdown_frame(self, shouldwait=True):
        pass
    def shutdown_sock(self):
        self.sock.close()
        self.closed = True
    def send_stream(self, frame_bytes, dest):
        content_length = len(frame_bytes)
        num_frames = (content_length // messages.MAX_APPLICATION_LENGTH) + 1
        max_size = messages.MAX_APPLICATION_LENGTH
        offset = 0
        stream_id = crypto.sha256sum(frame_bytes)
        total_sent = 0
        source = self.keyring.identity_id
        stream_struct = self.buffer_packs[messages.TYPE_STREAM]
        for i in range(1, num_frames+1):
            if content_length - offset >= max_size:
                body = frame_bytes[offset:offset+max_size]
                if offset == 0:
                    start_frame = stream_struct.pack(
                        messages.TYPE_STREAM,
                        max_size,
                        source,
                        dest,
                        self.current_frame_id,
                        messages.STREAM_OPEN,
                        stream_id
                    )
                    errcode = self.raw_send(start_frame + body)
                    if errcode is not None:
                        return errcode
                else:
                    continue_frame = stream_struct.pack(
                        messages.TYPE_STREAM,
                        max_size,
                        source,
                        dest,
                        self.current_frame_id,
                        messages.STREAM_CONTINUE,
                        stream_id
                    )
                    errcode = self.raw_send(continue_frame + body)
                    if errcode is not None:
                        return errcode
                offset += max_size
                total_sent += len(body)
            else:
                assert(i == num_frames)
                body = frame_bytes[offset:]
                stop_frame = stream_struct.pack(
                    messages.TYPE_STREAM,
                    len(body),
                    source,
                    dest,
                    self.current_frame_id,
                    messages.STREAM_CLOSE,
                    stream_id
                )
                self.raw_send(stop_frame + body)
                total_sent += len(body)
    def send_async_frame(self, frame_body, target_id):
        x3dh_info = self.keyring.create_new_asynchronous_session(target_id)
        if x3dh_info is None:
            if target_id in self.pending_encryption:
                self.pending_encryption[target_id].append(frame_body)
            else:
                self.pending_encryption[target_id] = [frame_body]
            return self.send_prekey_bundle_request(target_id)
        ek, spk, otk, salt, session_id = x3dh_info
        ratchet_header,ct = self.keyring.async_encrypt(session_id, frame_body)
        ct_length = len(ct)
        ratchet_struct = self.buffer_packs[messages.TYPE_RATCHET_FRAME]
        async_struct = self.buffer_packs[messages.ASYNC_FRAME]
        ratchet_frame = ratchet_struct.pack(
            messages.TYPE_RATCHET_FRAME,
            ct_length,
            self.keyring.identity_id,
            target_id,
            self.current_frame_id,
            ratchet_header
        )
        async_frame = async_struct.pack(
            messages.ASYNC_FRAME,
            ct_length + ratchet_struct.size,
            self.keyring.identity_id,
            target_id,
            self.current_frame_id,
            spk,
            otk,
            ek,
            salt
        )
        self.keyring.save_ratchet(session_id, target_id)
        return self.raw_send(async_frame + ratchet_frame + ct)
    def process_async_frame(self, frame_header, frame_body):
        frame_type, expected_length, source, dest, frame_id, spk, otk, ek, salt = frame_header
        peer_ek = crypto.get_public_dh_key_from_bytes(ek)
        session_id = self.keyring.update_asynchronous_session(
            source,
            salt,
            peer_ek,
            spk,
            otk
        )
        if session_id is None:
            return messages.HANDSHAKE_ERROR
        else:
            self.keyring.save_ratchet(session_id, source)
            body_type = struct.unpack("!B", frame_body[:1])[0]
            return self.process_frame(body_type, frame_body, len(frame_body))
    def process_ratchet_frame(self, frame_header, frame_body):
        frame_type, expected_length, source, dest, frame_id, ratchet_header = frame_header
        session_id = None
        if source in self.keyring.active_sessions:
            session_id = self.keyring.active_sessions[source]
        if session_id is None:
            return messages.CRYPTO_ERROR_UNKNOWN_SESSION_ID
        plaintext = self.keyring.async_decrypt(session_id, ratchet_header, frame_body)
        self.keyring.save_ratchet(session_id)
        if plaintext is None:
            return messages.CRYPTO_ERROR_DECRYPTION_FAILURE
        else:
            body_type = struct.unpack("!B", plaintext[:1])[0]
            return self.process_frame(body_type, plaintext, len(plaintext))
    def send_ratchet_frame(self, pt, dest, session_id):
        header, ct = self.keyring.async_encrypt(session_id, pt)
        self.keyring.save_ratchet(session_id)
        ct_length = len(ct)
        ratchet_struct = self.buffer_packs[messages.TYPE_RATCHET_FRAME]
        frame = ratchet_struct.pack(
            messages.TYPE_RATCHET_FRAME,
            ct_length,
            self.keyring.identity_id,
            dest,
            self.current_frame_id,
            header
        )
        if ct_length > messages.MAX_APPLICATION_LENGTH:
            return self.send_stream(frame + ct, dest)
        else:
            return self.raw_send(frame + ct)
    def send_group_key_frame(self, group_key_and_hash, identifier, recipients):
        group_key_struct = self.buffer_packs[messages.TYPE_GROUP_KEY]
        for recipient_id in recipients:
            frame = group_key_struct.pack(
                messages.TYPE_GROUP_KEY,
                0,
                self.keyring.identity_id,
                recipient_id,
                self.current_frame_id,
                identifier,
                group_key_and_hash
            )
            if recipient_id in self.keyring.active_sessions:
                session_id = self.keyring.active_sessions[recipient_id]
                self.send_ratchet_frame(frame, recipient_id, session_id)
            else:
                self.send_async_frame(frame, recipient_id)
    def process_group_key_frame(self, frame_header):
        frame_type, length, source, dest, frame_id, broadcast_id, group_key_and_hash = frame_header
        if broadcast_id not in self.pending_group_messages:
            self.pending_group_messages[broadcast_id] = {"source_id": source,
                                                        "key_and_hash": group_key_and_hash,
                                                        "ciphertext": None}
        else:
            if self.pending_group_messages[broadcast_id]["ciphertext"] is not None:
                plaintext = self.keyring.group_decrypt(
                    source,
                    group_key_and_hash,
                    self.pending_group_messages[broadcast_id]["ciphertext"]
                )
                if plaintext is not None:
                    del self.pending_group_messages[broadcast_id]
                    self.application_frames.put((plaintext, source, dest))
                else:
                    return messages.CRYPTO_ERROR_DECRYPTION_FAILURE
            else:
                self.pending_group_messages[broadcast_id]["source_id"] = source
                self.pending_group_messages[broadcast_id]["key_and_hash"] = group_key_and_hash
        return None
    def send_broadcast_request_message(self, message, recipients):
        #first generate a group key and encrypt the message with it
        group_key_and_hash, ciphertext = self.keyring.group_encrypt(message.encode())
        identifier = crypto.sha256sum(group_key_and_hash)
        self.send_group_key_frame(group_key_and_hash, identifier, recipients)
        broadcast_request_struct = self.buffer_packs[messages.TYPE_BROADCAST_REQUEST]
        number_of_recipients = len(recipients)
        recipient_id_length = number_of_recipients * 32
        frame = broadcast_request_struct.pack(
            messages.TYPE_BROADCAST_REQUEST,
            len(ciphertext) + recipient_id_length,
            self.keyring.identity_id,
            self.connection_id,
            self.current_frame_id,
            identifier,
            number_of_recipients
        )
        self.raw_send(frame + b"".join(recipients) + ciphertext)
    def send_broadcast_message(self, broadcast_id, source, dest, encrypted_content, length):
        broadcast_struct = self.buffer_packs[messages.TYPE_BROADCAST]
        frame = broadcast_struct.pack(
            messages.TYPE_BROADCAST,
            length,
            source,
            dest,
            self.current_frame_id,
            broadcast_id
        )
        self.application_frames.put((frame + encrypted_content, source, dest))
    def process_broadcast_message(self, frame_header, frame_body):
        frame_type, length, source, dest, frame_id, broadcast_id = frame_header
        if broadcast_id not in self.pending_group_messages:
            self.pending_group_messages[broadcast_id] = {"source_id": None,
                                                         "key_and_hash": None,
                                                         "ciphertext": frame_body}
        else:
            if self.pending_group_messages[broadcast_id]["key_and_hash"] is not None:
                plaintext = self.keyring.group_decrypt(
                    self.pending_group_messages[broadcast_id]["source_id"],
                    self.pending_group_messages[broadcast_id]["key_and_hash"],
                    frame_body
                )
                if plaintext is not None:
                    del self.pending_group_messages[broadcast_id]
                    self.application_frames.put((plaintext, source, dest))
                else:
                    return messages.CRYPTO_ERROR_DECRYPTION_FAILURE
            else:
                self.pending_group_messages[broadcast_id]["source_id"] = source
                self.pending_group_messages[broadcast_id]["ciphertext"] = frame_body
        return None
    def process_broadcast_request(self, frame_header, frame_body):
        frame_type, length, source, dest, frame_id, broadcast_id, num_recipients = frame_header
        recipient_ids_length = num_recipients * 32
        recipient_ids = frame_body[:recipient_ids_length]
        encrypted_content = frame_body[recipient_ids_length:]
        format_string = "!" + "32s" * num_recipients
        recipient_id_list = list(struct.unpack(format_string, recipient_ids))
        for recipient_id in recipient_id_list:
            self.send_broadcast_message(broadcast_id, source, recipient_id, encrypted_content, length - recipient_ids_length)
        return None
    def send_application_data(self, dest, content):
        content = content.encode()
        data_struct = self.buffer_packs[messages.TYPE_DATA]
        frame = data_struct.pack(
            messages.TYPE_DATA,
            len(content),
            self.keyring.identity_id,
            dest,
            self.current_frame_id
        )
        if dest != self.connection_id:
            if dest in self.keyring.active_sessions:
                session_id = self.keyring.active_sessions[dest]
                return self.send_ratchet_frame(frame + content, dest, session_id)
            else:
                return self.send_async_frame(frame + content, dest)
        else:
            return self.raw_send(frame + content)
