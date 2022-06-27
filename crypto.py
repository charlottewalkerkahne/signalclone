
import ratchet
from os import urandom
from struct import pack, unpack, iter_unpack, Struct
from cryptography.fernet import Fernet
from os.path import exists, join, isdir
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey



APP_NAME = b"Gesture(get it? like signal?)"

DEFAULT_PREKEY_NO = 50

def gen_kdf_salt():
    return urandom(32)

def gen_aesgcm_nonce():
    return urandom(12)

def gen_ephemeral_priv_key():
    return X25519PrivateKey.generate()

def get_public_dh_key_from_bytes(public_bytes):
    return X25519PublicKey.from_public_bytes(public_bytes)

def get_private_dh_key_from_bytes(private_bytes):
    return X25519PrivateKey.from_private_bytes(private_bytes)

def get_public_ed_key_from_bytes(public_bytes):
    return Ed25519PublicKey.from_public_bytes(public_bytes)

def get_private_ed_key_from_bytes(private_bytes):
    return Ed25519PrivateKey.from_private_bytes(private_bytes)


def sha256sum(data):
    if type(data) != type(b""):
        data = data.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

#someone could easily steal the identity key since it isn't encrypted
#the key is returned as bytes so that it can be saved to a db right away
def generate_dh_identity_key():
    private_key = X25519PrivateKey.generate()
    return private_key

def generate_ed_identity_key():
    private_key = Ed25519PrivateKey.generate()
    return private_key

#returns the serialized version of an X25519 Public key
def get_dh_public_bytes(dh_key):
    public_bytes = dh_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_bytes

#returns the serialized version of an X25519 private key
def get_dh_private_bytes(dh_key):
    private_bytes = dh_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_bytes

#returns the serialized version of an ed25519 public key
def get_ed_public_bytes(ed_key):
    public_bytes = ed_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_bytes

#returns the serialized version of an ed25519 private key
def get_ed_private_bytes(ed_key):
    private_bytes = ed_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_bytes

def get_identity_id(pub_ed_key, pub_dh_key):
    assert(pub_ed_key is not None and pub_dh_key is not None)
    ed_key_bytes = get_ed_public_bytes(pub_ed_key)
    dh_key_bytes = get_dh_public_bytes(pub_dh_key)
    key_hash = sha256sum(ed_key_bytes + dh_key_bytes)
    return key_hash


def dh_exchange(local_dh, peer_dh):
    return local_dh.exchange(peer_dh)

#computes x3dh agreement for the initiator
#and returns the key material that will be used to compute sk
#all local keys must be private keys to perform each dh step
def x3dh_exchange_initiator(ik_local, spk_peer, ek_local, ik_peer, otk_peer):
    dh1 = dh_exchange(ik_local, spk_peer)
    dh2 = dh_exchange(ek_local, ik_peer)
    dh3 = dh_exchange(ek_local, spk_peer)
    dh4 = dh_exchange(ek_local, otk_peer)
    key_material = dh1 + dh2 + dh3 + dh4
    return key_material

#computes x3dh agreement for responder and returns the key material used to compute sk
#all local keys must be private keys to perform each dh step
def x3dh_exchange_responder(ik_peer, spk_local, ik_local, ek_peer, otk_local):
    dh1 = dh_exchange(spk_local, ik_peer)
    dh2 = dh_exchange(ik_local, ek_peer)
    dh3 = dh_exchange(spk_local, ek_peer)
    dh4 = dh_exchange(otk_local, ek_peer)
    key_material = dh1 + dh2 + dh3 + dh4
    return key_material

def get_kdf(salt, output_length):
    kdf = HKDF(
        algorithm = hashes.SHA256(),
        length = output_length,
        salt = salt,
        info = APP_NAME,
        backend = default_backend()
    )
    return kdf

def root_key_kdf(rk, local_dh, peer_dh):
    dh_out = dh_exchange(local_dh, peer_dh)
    kdf = get_kdf(rk, 64)
    key = kdf.derive(dh_out)
    return key[:32], key[32:]

def chain_key_kdf(ck):
    kdf1 = get_kdf(ck, 32)
    key1 = kdf1.derive(b'\x01')
    kdf2 = get_kdf(ck, 32)
    key2 = kdf2.derive(b'\x02')
    return key1, key2


def derive_shared_key(secret, salt):
    kdf = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        info = APP_NAME, #the signal protocol recommends other ad such as hashed personal info like username or phone number
        backend = default_backend()
    )
    key = kdf.derive(secret)
    return key

def get_packed_ciphertext(nonce, ciphertext, ct_length):
    fmt_string = "!12s{}s".format(ct_length)
    packed_ciphertext = pack(fmt_string, nonce, ciphertext)
    return packed_ciphertext

def get_unpacked_ciphertext(ciphertext):
    ct_length = len(ciphertext) - 12
    fmt_string = "!12s{}s".format(ct_length)
    nonce,ct = unpack(fmt_string, ciphertext)
    return nonce,ct

def get_packed_otk_list(otk_list):
    format_string = "!" + "32s" * len(otk_list)
    return pack(format_string, *otk_list)

def get_unpacked_otk_list(raw_bytes):
    if len(raw_bytes) % 32 != 0:
        return None
    num_otk = len(raw_bytes) // 32
    format_string = "!" + "32s" * num_otk
    return list(next(iter_unpack(format_string, raw_bytes)))


def encrypt(key, plaintext, associated_data):
    encryptor = AESGCM(key)
    nonce = gen_aesgcm_nonce() #ensures that a new nonce is used each time we encrypt
    ct = encryptor.encrypt(nonce, plaintext, associated_data)
    return get_packed_ciphertext(nonce, ct, len(ct))

def decrypt(key, ciphertext, associated_data):
    decryptor = AESGCM(key)
    nonce,ct = get_unpacked_ciphertext(ciphertext)
    plaintext = decryptor.decrypt(nonce, ct, associated_data)
    if plaintext is None:
        pass
    return plaintext

def sign(signing_private_key, data):
    return signing_private_key.sign(data)

def verify(signing_public_key, signature, data):
    try:
        signing_public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def get_session_token(salt, peer_id, local_id):
    return sha256sum(salt)


#salt||sending public bytes||recv public bytes
def get_packed_dh_public_key(salt, public_key_s, public_key_r):
    format_string = "!32s32s32s"
    public_bytes_s = get_dh_public_bytes(public_key_s)
    public_bytes_r = get_dh_public_bytes(public_key_r)
    return pack(format_string, salt, public_bytes_s, public_bytes_r)

#unpacks salt and public_bytes and returns them as salt and public key
def get_unpacked_dh_public_key(packed_key):
    format_string = "!32s32s32s"
    salt, key_bytes_r, key_bytes_s = unpack(format_string, packed_key)
    dh_key_r = get_public_dh_key_from_bytes(key_bytes_r)
    dh_key_s = get_public_dh_key_from_bytes(key_bytes_s)
    return salt, dh_key_r, dh_key_s


class MemoryKeyStore:
    def __init__(self, keystorage, identity_id):
        self.keystorage = keystorage
        self.identity_id = identity_id
        self.identity_ed_key = get_private_ed_key_from_bytes(keystorage.fetch_by_type(identity_id, "ed"))
        self.identity_dh_key = get_private_dh_key_from_bytes(keystorage.fetch_by_type(identity_id, "dh"))

        self.peer_identity_ed_keys = {}
        self.peer_identity_dh_keys = {}

        self.incomplete_session_keys = {} #peer_id: {"enc": (local_salt, local_dh,peer_dh), "dec" (peer_salt, peer_dh, local_dh)}


        #session_id is hash(concat(hash(local_salt, local_id, peer_id)
        self.session_encryption_keys = {} # session_id: (session_key, aad)
        self.session_decryption_keys = {} # session_id: (session_key, aad)

        self.active_sessions = {} #peer_id: session_id

        self.ratchets = {} #session_id: ratchet

        self.group_key_packer = Struct("!32s32s") #32 byte private key and 32 byte plaintext hash

    def load_peers(self, addressbook):
        peers = addressbook.get_all_peer_ids()
        if peers is not None:
            for peer_id in peers:
                self.load_peer_identity_keys(peer_id)
                self.load_ratchet(peer_id)

    def load_ratchet(self, peer_id):
        ratchet_info = self.keystorage.fetch_ratchet_by_peer_id(peer_id)
        if ratchet_info is not None:
            self.ratchets[ratchet_info[0]] = ratchet.Ratchet.from_json(ratchet_info[2])
            self.active_sessions[peer_id] = ratchet_info[0]

    def save_ratchet(self, session_id, peer_id=None):
        session_ratchet = self.ratchets[session_id]
        ratchet_json = session_ratchet.to_json()
        if peer_id is None:
            self.keystorage.update_ratchet(session_id, ratchet_json)
        else:
            self.keystorage.insert_new_ratchet(session_id, peer_id, ratchet_json)

    #loads the identity keys for a single peer
    #returns True if peer exists and false otherwise
    def load_peer_identity_keys(self, peer_id):
        peer_ed_bytes = self.keystorage.fetch_by_type(peer_id, "ed")
        peer_dh_bytes = self.keystorage.fetch_by_type(peer_id, "dh")
        if peer_dh_bytes is not None and peer_ed_bytes is not None:
            peer_ed_key = get_public_ed_key_from_bytes(peer_ed_bytes)
            peer_dh_key = get_public_dh_key_from_bytes(peer_dh_bytes)
            self.peer_identity_ed_keys[peer_id] = peer_ed_key
            self.peer_identity_dh_keys[peer_id] = peer_dh_key

    #checks if a peer exists by checking the cache and then
    #checking the database
    def check_if_peer_exists(self, peer_id):
        exists_in_cache = (peer_id in self.peer_identity_dh_keys) and (peer_id in self.peer_identity_ed_keys)
        if not exists_in_cache:
            return self.load_peer_identity_keys(peer_id)
        return True

    #saves a new key to disk
    def save_key(self, identity_id, key_id, key_bytes, key_type):
        self.keystorage.insert_new_key(identity_id, key_id, key_bytes, key_type)

    #deletes a key from disk
    def delete_key(self, identity_id, key_id):
        self.keystorage.remove_key(identity_id, key_id)

    #generates a new otk and saves it to disk before returning the public bytes
    def gen_otk(self):
        new_otk = gen_ephemeral_priv_key()
        new_otk_public_bytes = get_dh_public_bytes(new_otk.public_key())
        new_otk_private_bytes = get_dh_private_bytes(new_otk)
        self.save_key(self.identity_id, new_otk_public_bytes, new_otk_private_bytes, key_type="otk")
        return new_otk_public_bytes

    #generates a new spk, signs it, and saves it to disk before returning both the public bytes and the sig
    def gen_spk(self):
        new_spk = gen_ephemeral_priv_key()
        spk_public_bytes = get_dh_public_bytes(new_spk.public_key())
        spk_private_bytes = get_dh_private_bytes(new_spk)
        spk_sig = sign(self.identity_ed_key, spk_public_bytes)
        self.save_key(self.identity_id, spk_public_bytes, spk_private_bytes+spk_sig, key_type="spk")
        return spk_public_bytes + spk_sig


    #returns the private key associated with key_id
    #functions that return private keys will return an actual key obj rather than
    #bytes because they will always be used for key exchange.
    #public keys will be returned as bytes because they may need to be sent
    def fetch_private_otk_key(self, key_id):
        private_bytes = self.keystorage.fetch_by_id(self.identity_id, key_id)
        self.delete_key(self.identity_id, key_id) #delete to make sure it can't be used again
        return get_private_dh_key_from_bytes(private_bytes)

    #returns a private spk associated with key_id
    #we only return the private key. We have no use for the signature because this function
    #should only be used to retrieve an owned private key for use in key exchange.
    #Basically, if this is getting called it means that the peer already has the public key and sig
    def fetch_private_spk(self, key_id):
        private_bytes_and_sig = self.keystorage.fetch_by_id(self.identity_id, key_id)
        private_key = get_private_dh_key_from_bytes(private_bytes_and_sig[:32])
        return private_key

    #returns a public otk associated with peer_id and then deletes it.
    #if none are found, then it returns None
    def fetch_public_otk(self, peer_id):
        pub_otk_bytes = self.keystorage.fetch_by_type(peer_id, "otk")
        if pub_otk_bytes is not None:
            self.delete_key(peer_id, pub_otk_bytes) #delete to make sure it isnt used again
        return pub_otk_bytes

    #returns a public spk and sig associated with peer_id
    def fetch_public_spk(self, peer_id):
        spk_list = self.keystorage.fetch_by_type(peer_id, "spk")
        if spk_list is None:
            return None
        if peer_id == self.identity_id:
            spk_pub = get_private_dh_key_from_bytes(spk_list[:32]).public_key()
            spk_pub_bytes = get_dh_public_bytes(spk_pub)
            spk_list = spk_pub_bytes + spk_list[32:]
        return spk_list

    #adds a peer otk to storage
    def add_public_otk(self, peer_id, key_bytes):
        self.save_key(peer_id, key_bytes, key_bytes, "otk")

    #verifies the new key and sig deletes the previous key and then adds this new one
    def add_public_spk(self, peer_id, key_bytes, key_sig):
        signing_key = self.peer_identity_ed_keys[peer_id]
        if verify(signing_key, key_sig, key_bytes):
            spk = self.keystorage.fetch_by_type(peer_id, "spk")
            if spk is not None:
                self.delete_key(peer_id, spk[:32]) #the key_id is also the public key
            self.save_key(peer_id, key_bytes, key_bytes + key_sig, "spk")
            return True
        else:
            return False

    #saves an identity_key for a peer
    def add_public_ed_identity_key(self, peer_id, key_bytes):
        self.save_key(peer_id, key_bytes, key_bytes, "ed")

    #saves an identity_key for a peer
    def add_public_dh_identity_key(self, peer_id, key_bytes):
        self.save_key(peer_id, key_bytes, key_bytes, "dh")


    #generates dh keys for use in ephemeral key exchange
    #this is done synchronously as opposed to x3dh
    def create_new_synchronous_session(self, peer_id):
        if peer_id in self.active_sessions:
            return None
        local_salt = gen_kdf_salt()
        local_dh_s = gen_ephemeral_priv_key()
        local_dh_r = gen_ephemeral_priv_key()
        self.incomplete_session_keys[peer_id] = {"enc": None, "dec": None}
        self.incomplete_session_keys[peer_id]["enc"] = {"salt": local_salt, "l_dh": local_dh_s, "r_dh": None}
        self.incomplete_session_keys[peer_id]["dec"] = {"salt": None, "r_dh": None, "l_dh": local_dh_r}
        return peer_id

    def update_synchronous_session(self, peer_id, peer_salt, peer_dh_r, peer_dh_s):
        if peer_id in self.active_sessions:
            print("peer already connected")
            return None
        if peer_id not in self.incomplete_session_keys:
            self.create_new_synchronous_session(peer_id)
        self.incomplete_session_keys[peer_id]["dec"]["salt"] = peer_salt
        self.incomplete_session_keys[peer_id]["dec"]["r_dh"] = peer_dh_s
        self.incomplete_session_keys[peer_id]["enc"]["r_dh"] = peer_dh_r
        return peer_id

    def remove_synchronous_session(self, peer_id):
        if peer_id in self.active_sessions:
            encryptor_session_id = self.active_sessions[peer_id][0]
            decryptor_session_id = self.active_sessions[peer_id][1]
            del self.session_decryption_keys[decryptor_session_id]
            del self.session_encryption_keys[encryptor_session_id]
            del self.active_sessions[peer_id]
        if peer_id in self.incomplete_session_keys:
            del self.incomplete_session_keys[peer_id]

    def wrap_synchronous_session(self, peer_id):
        complete_session = self.incomplete_session_keys[peer_id]
        sending_key_material = dh_exchange(complete_session["enc"]["l_dh"], complete_session["enc"]["r_dh"])
        receiving_key_material = dh_exchange(complete_session["dec"]["l_dh"], complete_session["dec"]["r_dh"])

        sending_salt = complete_session["enc"]["salt"]
        receiving_salt = complete_session["dec"]["salt"]

        sending_key = derive_shared_key(sending_key_material, sending_salt)
        receiving_key = derive_shared_key(receiving_key_material, receiving_salt)

        encryptor_id = sha256sum(sending_salt + self.identity_id + peer_id)
        decryptor_id = sha256sum(receiving_salt + peer_id + self.identity_id)


        encryption_aad = sha256sum(sending_salt + peer_id)
        decryption_aad = sha256sum(receiving_salt + self.identity_id)
        self.session_encryption_keys[encryptor_id] = (sending_key, encryption_aad)
        self.session_decryption_keys[decryptor_id] = (receiving_key, decryption_aad)

        #set the incomplete_session_key to None so we know that it is complete
        self.incomplete_session_keys[peer_id] = None
        self.active_sessions[peer_id] = (encryptor_id, decryptor_id)


    #this creates an asynchronous session using x3dh
    #This requires that we have a peer otk saved. The actual
    #x3dh protocol listed on the signal developer docs site
    #makes the otk optional however. If the client has everything
    #required then it performs the
    def create_new_asynchronous_session(self, peer_id):
        if peer_id not in self.peer_identity_dh_keys:
            self.load_peer_identity_keys(peer_id)
            if peer_id not in self.peer_identity_dh_keys:
                return None
        peer_dh_ik = self.peer_identity_dh_keys[peer_id]
        ek_local = gen_ephemeral_priv_key()
        peer_spk_bytes = self.fetch_public_spk(peer_id)
        peer_otk_bytes = self.fetch_public_otk(peer_id)
        if peer_spk_bytes is None or peer_otk_bytes is None:
            return None
        else:
            peer_spk = get_public_dh_key_from_bytes(peer_spk_bytes[:32])
            peer_otk = get_public_dh_key_from_bytes(peer_otk_bytes)
            ek_bytes = get_dh_public_bytes(ek_local.public_key())
            local_salt = gen_kdf_salt()
            sk_material = x3dh_exchange_initiator(
                self.identity_dh_key, peer_spk, ek_local, peer_dh_ik, peer_otk)
            session_id = sha256sum(local_salt)
            sk = derive_shared_key(sk_material, local_salt)
            self.ratchets[session_id] = ratchet.ratchet_init_request(sk, peer_spk)
            self.active_sessions[peer_id] = session_id
            return ek_bytes, peer_spk_bytes, peer_otk_bytes, local_salt, session_id


    def update_asynchronous_session(self, peer_id, peer_salt, peer_ek, spk_id, otk_id):
        peer_dh_ik = self.peer_identity_dh_keys[peer_id]
        spk_priv = self.fetch_private_spk(spk_id)
        otk_priv = self.fetch_private_otk_key(otk_id)
        sk_material = x3dh_exchange_responder(peer_dh_ik, spk_priv, self.identity_dh_key, peer_ek, otk_priv)
        sk = derive_shared_key(sk_material, peer_salt)
        session_id = sha256sum(peer_salt)
        self.ratchets[session_id] = ratchet.ratchet_init_response(sk, spk_priv)
        self.active_sessions[peer_id] = session_id
        return session_id

    def session_encrypt(self, session_id, pt):
        sealing_key, aad = self.session_encryption_keys[session_id]
        self.session_encryption_keys[session_id] = (sha256sum(sealing_key), aad)
        return encrypt(sealing_key, pt, aad)

    def session_decrypt(self, session_id, nonce_ct):
        decryption_key, aad = self.session_decryption_keys[session_id]
        self.session_decryption_keys[session_id] = (sha256sum(decryption_key), aad)
        return decrypt(decryption_key, nonce_ct, aad)

    def async_encrypt(self, session_id, pt):
        encrypted = self.ratchets[session_id].ratchet_encrypt(pt, session_id)
        self.save_ratchet(session_id)
        return encrypted

    def async_decrypt(self, session_id, header, nonce_ct):
        self.save_ratchet(session_id) #save the ratchet before attempting to decrypt
        try:
            decrypted = self.ratchets[session_id].ratchet_decrypt(header, nonce_ct, session_id)
        except:
            return None
        if decrypted is not None:
            self.save_ratchet(session_id)
        return decrypted

    #generate a new key K and encrypt the plaintext with it
    #return concat(key, hash(plaintext)), encrypt_K(plaintext)
    def group_encrypt(self, plaintext):
        group_key = AESGCM.generate_key(256)
        plaintext_hash = sha256sum(plaintext)
        ciphertext = encrypt(group_key, plaintext, self.identity_id)
        packed_key_and_hash = self.group_key_packer.pack(group_key, plaintext_hash)
        return packed_key_and_hash, ciphertext

    #unpack key K and hash(plaintext), check that hash(plaintext) == hash(decrypt_K(ciphertext))
    #if yes - return the plaintext
    #otherwise return None
    def group_decrypt(self, source_id, group_key_and_hash, ciphertext):
        group_key, expected_hash = self.group_key_packer.unpack(group_key_and_hash)
        plaintext = decrypt(group_key, ciphertext, source_id)
        if plaintext is None:
            return None
        plaintext_hash = sha256sum(plaintext)
        if not constant_time.bytes_eq(plaintext_hash, expected_hash):
            return None
        return plaintext





