import crypto
import messages
import json
import utils
MAX_SKIP = 100

#a lot of this code is copied directly from the double ratchet developer docs
#on signal.org
class Ratchet:
    def __init__(self, dhs, dhr, rk, cks, ckr, ns, nr, pn, mkskipped):
        self.dhs = dhs
        self.dhr = dhr
        self.rk = rk
        self.cks = cks
        self.ckr = ckr
        self.ns = ns
        self.nr = nr
        self.pn = pn
        self.mkskipped = mkskipped

    #deserialize session info from json
    @classmethod
    def from_json(cls, json_obj):
        ratchet_dict = json.loads(json_obj)
        mkskipped = {}
        dhs = None
        dhr = None
        rk = None
        cks = None
        ckr = None
        if len(ratchet_dict['mkskipped']) > 0:
            for (dh, n), mk in ratchet_dict['mkskipped'].items():
                mkskipped[utils.decode_64(dh), n] = utils.decode_64(mk)
        if ratchet_dict['dhs'] is not None:
            dhs = crypto.get_private_dh_key_from_bytes(utils.decode_64(ratchet_dict['dhs']))
        if ratchet_dict['dhr'] is not None:
            dhr = utils.decode_64(ratchet_dict['dhr'])
        if ratchet_dict['rk'] is not None:
            rk = utils.decode_64(ratchet_dict['rk'])
        if ratchet_dict['cks'] is not None:
            cks = utils.decode_64(ratchet_dict['cks'])
        if ratchet_dict['ckr'] is not None:
            ckr = utils.decode_64(ratchet_dict['ckr'])
        return Ratchet(
            dhs,
            dhr,
            rk,
            cks,
            ckr,
            ratchet_dict['ns'],
            ratchet_dict['nr'],
            ratchet_dict['pn'],
            mkskipped
        )
    #serialize session info to json
    def to_json(self):
        json_dict = {}
        json_dict['dhs'] = utils.encode_64(crypto.get_dh_private_bytes(self.dhs))
        if self.dhr is not None:
            if type(self.dhr) != type(b"\x00"):
                json_dict['dhr'] = utils.encode_64(crypto.get_dh_public_bytes(self.dhr))
            else:
                json_dict['dhr'] = utils.encode_64(self.dhr)
        else:
            json_dict['dhr'] = None
        if self.rk is not None:
            json_dict['rk'] = utils.encode_64(self.rk)
        else:
            json_dict['rk'] = None
        if self.cks is not None:
            json_dict['cks'] = utils.encode_64(self.cks)
        else:
            json_dict['cks'] = None
        if self.ckr is not None:
            json_dict['ckr'] = utils.encode_64(self.ckr)
        else:
            json_dict['ckr'] = None
        json_dict['ns'] = self.ns
        json_dict['nr'] = self.nr
        json_dict['pn'] = self.pn
        if len(self.mkskipped) > 0:
            mkskipped = {}
            for (dh, ns), mk in self.mkskipped.items():
                if type(dh) != type(b"\x00"):
                    mkskipped[(utils.encode_64(crypto.get_dh_public_bytes(dh)), ns)] = utils.encode_64(mk)
                else:
                    mkskipped[(utils.encode_64(dh), ns)] = utils.encode_64(mk)
            json_dict['mkskipped'] = mkskipped
        else:
            json_dict['mkskipped'] = self.mkskipped
        json_ratchet = json.dumps(json_dict)
        return json_ratchet

    def ratchet_encrypt(self, plaintext, ad):
        self.cks, mk = crypto.chain_key_kdf(self.cks)
        local_pub = self.dhs.public_key()
        header = messages.RatchetHeader(local_pub, self.pn, self.ns)
        self.ns += 1
        return header.to_bytes(), crypto.encrypt(mk, plaintext, ad + header.to_bytes())
    def ratchet_decrypt(self, header, ciphertext, ad):
        header = messages.RatchetHeader.from_bytes(header)
        plaintext = self.try_skipped_message_keys(header, ciphertext, ad)
        if plaintext != None:
            return plaintext
        if header.dh != self.dhr:
            self.skip_messages_keys(header.pn)
            self.dh_ratchet(header)
        self.skip_messages_keys(header.ns)
        self.ckr, mk = crypto.chain_key_kdf(self.ckr)
        self.nr += 1
        return crypto.decrypt(mk, ciphertext, ad+header.header_bytes)
    #see if this is an out of order message encrypted with an older key
    def try_skipped_message_keys(self, header, ciphertext, ad):
        if (header.dh, header.ns) in self.mkskipped:
            mk = self.mkskipped[(header.dh, header.ns)]
            del self.mkskipped[(header.dh, header.ns)]
            return crypto.decrypt(mk, ciphertext, ad + header.header_bytes)
        else:
            return None
    #generate and save message keys to decrypt out of order messages
    def skip_messages_keys(self, until):
        if self.nr + MAX_SKIP < until:
            raise Exception("Too many skipped messages")
        if self.ckr != None:
            while self.nr < until:
                self.ckr, mk = crypto.chain_key_kdf(self.ckr)
                self.mkskipped[(self.dhr, self.nr)] = mk
                self.nr += 1
        else:
            pass
    #ratchet the sending and receiving chain and generate a new dh keypair
    def dh_ratchet(self, header):
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr = header.dh
        dhr_pub_key = crypto.get_public_dh_key_from_bytes(self.dhr)
        self.rk, self.ckr = crypto.root_key_kdf(self.rk, self.dhs, dhr_pub_key)
        self.dhs = crypto.gen_ephemeral_priv_key()
        self.rk, self.cks = crypto.root_key_kdf(self.rk, self.dhs, dhr_pub_key)





#first agree on some SK through X3DH/sesame
#and then initialize a new ratchet with the function below
#this function is called by the requesting endpoint in the original key agreement
def ratchet_init_request(SK, peer_dh_public):
    new_local_dh = crypto.gen_ephemeral_priv_key()
    root_key, sending_chain_key = crypto.root_key_kdf(SK, new_local_dh, peer_dh_public)
    receiving_chain_key = None
    number_sent = 0
    number_received = 0
    previous_number_sent = 0
    skipped_message_keys = {}
    return Ratchet(
        dhs = new_local_dh,
        dhr = crypto.get_dh_public_bytes(peer_dh_public),
        rk = root_key,
        cks = sending_chain_key,
        ckr = receiving_chain_key,
        ns = number_sent,
        nr = number_received,
        pn = previous_number_sent,
        mkskipped = skipped_message_keys
    )


#similar to the function above except this one is called by
#the responding endpoint in the original key agreement
def ratchet_init_response(SK, local_dh_keypair):
    peer_dh_public = None
    root_key = SK
    sending_chain_key = None
    receiving_chain_key = None
    number_sent = 0
    number_received = 0
    previous_number_sent = 0
    skipped_message_keys = {}
    return Ratchet(
        dhs = local_dh_keypair,
        dhr = peer_dh_public,
        rk = root_key,
        cks = sending_chain_key,
        ckr = receiving_chain_key,
        ns = number_sent,
        nr = number_received,
        pn = previous_number_sent,
        mkskipped = skipped_message_keys
    )