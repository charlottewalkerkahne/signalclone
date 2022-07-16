import unittest
import storage
import crypto
import utils
import sqlite3


class TestCryptoFunctions(unittest.TestCase):

    def setUp(self):
        self.dh_key_1 = b'0S\xcf\xed\x88\x8c\xae\x02\x1c\xeayF_\x88\xf9\x86T\t\x95\x0e27}[5\xc0|\xdfN\x1c\x0ej'
        self.dh_key_1_pub = b'+\x1c\xc0\xff\xc4\x9d\x917d\xc2\xc9U2P\x02\xcf\xc1$\xbaR\x08\xe5\x07\x91wE\x84_\xda\xd3\xf8\x08'

        self.dh_key_2 = b'\xb8tn\xe0\xbah]\xf2\x0b\xfe\xd0A,p\xde\x00~b\x0b\xccAz\xf3I\xb4\x9f\xb4\xefT\xc3 E'
        self.dh_key_2_pub = b'\xef;\xa8\x13\xc6c\xc3?\x07\xff&|>\xa8\xeb\xd7\x00\xcb4\xb0S,\x86\x03\x17%\x85I\xf9\xc9\x82\x13'

    def test_get_packed_ciphertext(self):
        #use a random nonce
        nonce = b'v3I\x958\x1f]Q\x1a\xfb\x84\x9f'
        #use random bytes as a ciphertext since we are not testing decrypt here
        ct = b"\xf9\x18\xa6\xfbty\xc4\xea\x1c\xd8\x99\xfa\xdb\xd26 \xd0\xe2\x980\xd4\xe6\x0fP\xb8\xf6\x10\x91\xe9\xdc\xdae\xa0F\xc7t{\xd34\x11\xf8\x89;\xa3\xdc\x7f\x9a{\xaf\xcb\xfe\x80\x87\xa3\x89qV\xaa\x95N\x83\xfa \x93f*\xbbp\x05.Rc$\xf0\xa8:-\xe1G\xdd\x14-;\x91V4\xfeHUE&R\xef\x82\x16f\x98\xe3k\x13'\\!\x859R\xfeHJR\x9b \xc9\xb5t(\x93\xec(W"
        ct_length = 120
        packed = crypto.get_packed_ciphertext(nonce, ct, ct_length)
        self.assertEqual(packed, nonce+ct)

    def test_unpacked_ciphertext(self):
        ciphertext = b"v3I\x958\x1f]Q\x1a\xfb\x84\x9f\xf9\x18\xa6\xfbty\xc4\xea\x1c\xd8\x99\xfa\xdb\xd26 \xd0\xe2\x980\xd4\xe6\x0fP\xb8\xf6\x10\x91\xe9\xdc\xdae\xa0F\xc7t{\xd34\x11\xf8\x89;\xa3\xdc\x7f\x9a{\xaf\xcb\xfe\x80\x87\xa3\x89qV\xaa\x95N\x83\xfa \x93f*\xbbp\x05.Rc$\xf0\xa8:-\xe1G\xdd\x14-;\x91V4\xfeHUE&R\xef\x82\x16f\x98\xe3k\x13'\\!\x859R\xfeHJR\x9b \xc9\xb5t(\x93\xec(W"
        nonce, ct = crypto.get_unpacked_ciphertext(ciphertext)
        self.assertEqual(nonce, b'v3I\x958\x1f]Q\x1a\xfb\x84\x9f')
        self.assertEqual(ct, b"\xf9\x18\xa6\xfbty\xc4\xea\x1c\xd8\x99\xfa\xdb\xd26 \xd0\xe2\x980\xd4\xe6\x0fP\xb8\xf6\x10\x91\xe9\xdc\xdae\xa0F\xc7t{\xd34\x11\xf8\x89;\xa3\xdc\x7f\x9a{\xaf\xcb\xfe\x80\x87\xa3\x89qV\xaa\x95N\x83\xfa \x93f*\xbbp\x05.Rc$\xf0\xa8:-\xe1G\xdd\x14-;\x91V4\xfeHUE&R\xef\x82\x16f\x98\xe3k\x13'\\!\x859R\xfeHJR\x9b \xc9\xb5t(\x93\xec(W")

    def test_get_packed_otk_list(self):
        otk_list = [self.dh_key_1_pub, self.dh_key_2_pub]
        packed_list = crypto.get_packed_otk_list(otk_list)
        self.assertEqual(packed_list, self.dh_key_1_pub + self.dh_key_2_pub)

    def test_get_unpacked_otk_list(self):
        packed_list = self.dh_key_1_pub + self.dh_key_2_pub
        key1, key2 = crypto.get_unpacked_otk_list(packed_list)
        self.assertEqual(key1, self.dh_key_1_pub)
        self.assertEqual(key2, self.dh_key_2_pub)

    #test what happens if we try to unpack a list with bad length
    #since a public key will always be 32 bytes
    def test_get_unpacked_otk_list_none(self):
        packed_list = b'v3I\x958\x1f]Q\x1a\xfb\x84\x9f' + self.dh_key_1_pub + self.dh_key_2_pub
        unpacked_list = crypto.get_unpacked_otk_list(packed_list)
        self.assertEqual(unpacked_list, None)

    def test_get_packed_dh_public_key(self):
        #use a random salt
        salt = b'\xc3\xb7\xab;\x1cU\xc1Mb\xe0\x07\xb5\xd3n\x1d\xff;\x04\xc6\xdc\xfb\xcc\x86\xec\x18\x8cR\xae\x1f\x7f\xe1\xea'
        public_key_s = crypto.get_private_dh_key_from_bytes(self.dh_key_1).public_key()
        public_key_r = crypto.get_private_dh_key_from_bytes(self.dh_key_2).public_key()

        packed_dh_key = crypto.get_packed_dh_public_key(salt, public_key_s, public_key_r)
        self.assertEqual(packed_dh_key, salt + self.dh_key_1_pub + self.dh_key_2_pub)

    def test_get_unpacked_dh_public_key(self):
        #use a random salt
        expected_salt = b'o\x95\xa1\xdcF\xbd\x8d\x0c@J\x9c\xc1\x04u<yt\xed\xb0\xc2a\\\x11@I\xb3,\x1d"r\x87['
        expected_key_r = self.dh_key_1_pub
        expected_key_s = self.dh_key_2_pub
        salt, dh_key_r, dh_key_s = crypto.get_unpacked_dh_public_key(expected_salt + expected_key_r + expected_key_s)

        actual_key_r = crypto.get_dh_public_bytes(dh_key_r)
        actual_key_s = crypto.get_dh_public_bytes(dh_key_s)

        self.assertEqual(salt, expected_salt)
        self.assertEqual(actual_key_r, expected_key_r)
        self.assertEqual(actual_key_s, expected_key_s)

    def test_chain_key_kdf(self):
        #use a random chain key
        ck = b'\x7f\x84\x9c5\xf1\xa2\x16@\x11$\x17\xa8\xda\xbd\xe8p\x7f\xe1\xac\x95=\xe1\xb8\xfc\xde/\x07F\x8b\xe7F\xe7'
        key1,key2 = crypto.chain_key_kdf(ck)
        #if this fails then that's bad because the break in resistant property of the double ratchet
        #relies on the fact that a key used to encrypt a message cannot be used to calculate future keys alone
        self.assertFalse(key1 == key2)

    def test_root_key_kdf(self):
        #use a random root key
        rk = b'\x7f\x84\x9c5\xf1\xa2\x16@\x11$\x17\xa8\xda\xbd\xe8p\x7f\xe1\xac\x95=\xe1\xb8\xfc\xde/\x07F\x8b\xe7F\xe7'
        local_dh = crypto.get_private_dh_key_from_bytes(self.dh_key_1)
        peer_dh = crypto.get_public_dh_key_from_bytes(self.dh_key_2_pub)
        key1,key2 = crypto.root_key_kdf(rk, local_dh, peer_dh)
        self.assertFalse(key1 == key2)


class TestAddressBookMethods(unittest.TestCase):

    def setUp(self):
        self.client_storage = storage.ThreadSafeConnection(sqlite3.connect(":memory:"))
        cur = self.client_storage.cursor().cursor #get the underlying cursor from the threadsafe cursor
        storage.create_addressbook(cur)

        #add people to addressbook

        username_1 = "client1"
        identity_id_1 = 'WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro='
        username_1_is_server = 0

        username_2 = "client2"
        identity_id_2 = 'zv+TT6sQMnUxmhSp7tCM9bU1VDRG5Va+FZfmpJZBjGs='
        username_2_is_server = 0

        username_3 = "client3"
        identity_id_3 = 'PKElsHqrhIlR28WWABQPwqkuU/+bxig9+GAgznvlcbc='
        username_3_is_server = 0

        username_4 = "server"
        identity_id_4 = '20yvrIncQBmWtlv+G++/BUHYjKG0ua6dang3LenM2O4='
        username_4_is_server = 1

        self.contact_list = [
            (identity_id_1, username_1, username_1_is_server),
            (identity_id_2, username_2, username_2_is_server),
            (identity_id_3, username_3, username_3_is_server),
            (identity_id_4, username_4, username_4_is_server)
        ]
        cur.executemany("INSERT INTO addressbook values (?, ?, ?)", self.contact_list)

        self.addressbook = storage.AddressBook("client1", self.client_storage)

    def test_get_all_peer_ids(self):
        expected_peer_ids = [utils.decode_64(userid) for (userid, username, is_server) in self.contact_list]
        actual_peer_ids = self.addressbook.get_all_peer_ids()
        self.assertEqual(expected_peer_ids, actual_peer_ids)

    def test_add_contact(self):
        new_username = "client4"
        new_id = b'i\xb8\xce\x00\x83\xfc)\xe9ev\x83A\xae.J\x8eP\xb8\x92\x0f@\xbc(\xa8\xa4\x92G>aH\x1c0'
        is_server = False
        self.addressbook.add_contact(new_id, new_username, is_server)
        cur = self.client_storage.cursor().cursor
        cur.execute("SELECT * FROM addressbook where username='client4'")
        client_info = cur.fetchall()
        self.assertEqual(len(client_info), 1)
        (encoded_id, username, is_server_num) = client_info[0]
        self.assertEqual(utils.decode_64(encoded_id), new_id)
        self.assertEqual(username, new_username)
        self.assertFalse(is_server_num == 1)

    def test_update_contact_username(self):
        target_id = utils.decode_64('WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=') #client1 id
        new_username = "new_client_1"
        self.addressbook.update_contact_username(target_id, new_username)
        cur = self.client_storage.cursor().cursor
        cur.execute("SELECT * FROM addressbook where identity_id='WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro='")
        client_info = cur.fetchall()
        self.assertEqual(len(client_info), 1)
        (encoded_id, username, is_server_num) = client_info[0]

        self.assertEqual(utils.decode_64(encoded_id), target_id)
        self.assertEqual(username, new_username)
        self.assertFalse(is_server_num == 1)

    def test_fetch_username_by_id(self):
        target_id = utils.decode_64('WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=') #client1 id
        expected_username = "client1"
        actual_username = self.addressbook.fetch_username_by_id(target_id)
        self.assertEqual(actual_username, expected_username)

    def test_fetch_username_by_id_not_found(self):
        target_id = b'i\xb8\xce\x00\x83\xfc)\xe9ev\x83A\xae.J\x8eP\xb8\x92\x0f@\xbc(\xa8\xa4\x92G>aH\x1c0'
        return_val = self.addressbook.fetch_username_by_id(target_id)
        self.assertEqual(return_val, None)

    def test_fetch_id_by_username(self):
        expected_id = utils.decode_64('WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=') #client1 id
        target_username = "client1"
        actual_id = self.addressbook.fetch_id_by_username(target_username)
        self.assertEqual(expected_id, actual_id)

    def test_fetch_id_by_username_not_found(self):
        target_username = "nonexistantusername"
        return_val = self.addressbook.fetch_id_by_username(target_username)
        self.assertEqual(return_val, None)

    def test_remove_contact(self):
        target_id = utils.decode_64('WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=') #client1 id
        self.addressbook.remove_contact(target_id)
        cur = self.client_storage.cursor().cursor
        cur.execute("SELECT * FROM addressbook WHERE identity_id='WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro='")
        returned_contacts = cur.fetchall()
        self.assertTrue(len(returned_contacts) == 0)


class TestKeyStorageMethods(unittest.TestCase):


    def setUp(self):
        self.client_storage = storage.ThreadSafeConnection(sqlite3.connect(":memory:"))
        cur = self.client_storage.cursor().cursor  # get the underlying cursor from the threadsafe cursor
        storage.create_keystorage(cur)

        # add keys to keystorage

        #these can all be random because we aren't going to use them here
        identity_id_1 = 'WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro='

        #the key id does not have to match the key
        ed_key_1_id = '7CYUo0bKtjrx/Xsq39jj8JjikG9SUsi9Y5X1l81aFdM='
        ed_key_1_bytes = b'\xb3&\xe3\x01\xd8\\\x1d\x11\xc1\x16l\x94x\xec\xaa\xaf\xaa\xe2\xbc\xd1\x1f_?\xf4^i\x0c\xe5\xb8\xac\xf2\x04'
        ed_key_1_type = "ed"

        dh_key_1_id = 'v2EAM+kvfASBIQ2CF+1DwhzLszvvumKQIBNDY6ryZfE='
        dh_key_1_bytes = b'\xf2\x86(\x0eP\x82\xcd\xad\xcft\x9f\xfc\xa4\xc4\xb4\x1b\x11\x85\x95\xa20\x0826\xc8\xcd[my\x00\x80\xd2'
        dh_key_1_type = "dh"


        identity_id_2 = 'zv+TT6sQMnUxmhSp7tCM9bU1VDRG5Va+FZfmpJZBjGs='

        ed_key_2_id = 'fSfgfFm7YBNe8T4+29BCnqjpT9gK1YgslmKwOc/Qv44='
        ed_key_2_bytes = b'\xf9g`i\xb5\xdc\xd1\xce\x97u\x12\xd4\xe7\xff{\xf4\xb8P\x8c\xb30\xe0\xa0\xa5\x94\x82JDm\xb9\xad\x82'
        ed_key_2_type = "ed"

        dh_key_2_id = 'hxPxuayG+H4JY1c8Izvo51VMGguXz7rGBKriKWzw+oM='
        dh_key_2_bytes = b'C2\xf5\xf3Q\xdcW@\xd5\xf75\xf4G\x9d\x94\x0eI\x8e\xb2G\x043S\xbcf\x81\x8bjJ}Y+'
        dh_key_2_type = "dh"

        self.key_list = [
            (identity_id_1, ed_key_1_id, ed_key_1_bytes, ed_key_1_type),
            (identity_id_1, dh_key_1_id, dh_key_1_bytes, dh_key_1_type),
            (identity_id_2, ed_key_2_id, ed_key_2_bytes, ed_key_2_type),
            (identity_id_2, dh_key_2_id, dh_key_2_bytes, dh_key_2_type)
        ]
        cur.executemany("INSERT INTO keystorage values (?, ?, ?, ?)", self.key_list)

        self.keystorage = storage.KeyStorage(identity_id_1, self.client_storage)

    def test_insert_new_key(self):
        new_identity_id = utils.decode_64('cceBlNUuXS4l1YhYyv9jvBB4nwAF03RJb7vwxZGCI3k=')
        new_key_id = utils.decode_64('C1jKxdECHE2qDwtRXSS1ME9zUBqh7WpX0etE6QhWgRA=')
        new_key_bytes = b'\xbb\x89g\x95`,\xdd\x0b\xa6\xb8\xfa\x9c\x1b\x93Y\xed\n\xba$\xdb\xc8\xe7<U\x96N\xe4>/,\xf5\xa8'
        new_key_type = "ed"
        self.keystorage.insert_new_key(new_identity_id, new_key_id, new_key_bytes, "ed")
        cur = self.client_storage.cursor().cursor
        cur.execute("SELECT * FROM keystorage WHERE identity_id='cceBlNUuXS4l1YhYyv9jvBB4nwAF03RJb7vwxZGCI3k='")
        fetched_key = cur.fetchall()
        self.assertTrue(len(fetched_key) == 1)

        iden_id, key_id, key_bytes, key_type = fetched_key[0]
        self.assertEqual(new_identity_id, utils.decode_64(iden_id))
        self.assertEqual(new_key_id, utils.decode_64(key_id))
        self.assertEqual(new_key_bytes, key_bytes)
        self.assertEqual(new_key_type, key_type)

    def test_fetch_by_id(self):
        target_identity_id = utils.decode_64('WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=')
        target_key_id = utils.decode_64('7CYUo0bKtjrx/Xsq39jj8JjikG9SUsi9Y5X1l81aFdM=')
        expected_key_bytes = b'\xb3&\xe3\x01\xd8\\\x1d\x11\xc1\x16l\x94x\xec\xaa\xaf\xaa\xe2\xbc\xd1\x1f_?\xf4^i\x0c\xe5\xb8\xac\xf2\x04'

        fetched_key = self.keystorage.fetch_by_id(target_identity_id, target_key_id)

        self.assertTrue(fetched_key is not None)
        self.assertEqual(fetched_key, expected_key_bytes)

    def test_remove_key(self):
        target_identity_id = utils.decode_64('WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=')
        target_key_id = utils.decode_64('7CYUo0bKtjrx/Xsq39jj8JjikG9SUsi9Y5X1l81aFdM=')

        self.keystorage.remove_key(target_identity_id, target_key_id)
        cur = self.client_storage.cursor().cursor
        cur.execute("SELECT * FROM keystorage WHERE identity_id='WacZfdkQ+oKMI3vy/FbTUk2YV33kMs+d1bmE4Pk/5ro=' and key_id='7CYUo0bKtjrx/Xsq39jj8JjikG9SUsi9Y5X1l81aFdM='")
        fetched_key = cur.fetchall()
        self.assertTrue(len(fetched_key) == 0)

    def test_insert_new_ratchet(self):
        new_session_id = b"\xce\x82\x1f\x9e\x1b\x8e\xee\xfc\xe5\xa6\x88\xac\x7f\xa1\x06\xf8\x8a`K<\x83\x956'\xc3L\xee\x13\xc5\x04(\x8f"
        new_peer_id = b'\xb2\xfe\'j\x9b\x8e}\xb3^\x99\xe8A!\xaf\xa2H\x0b\xfd\x1e\xe8\xaa\x0f\xf9\xd7\x98\xbe\x1f\xca\x96]"A'
        new_ratchet_info = "jsonencodedratchet"
        self.keystorage.insert_new_ratchet(new_session_id, new_peer_id, new_ratchet_info)

        cur = self.client_storage.cursor().cursor
        cur.execute("SELECT * FROM ratchetstorage") #should only be one entry at this point
        ratchet_data = cur.fetchall()
        self.assertTrue(ratchet_data is not None)

        session_id, peer_id, ratchet_info = ratchet_data[0]
        self.assertEqual(session_id, utils.encode_64(new_session_id))
        self.assertEqual(peer_id, utils.encode_64(new_peer_id))
        self.assertEqual(ratchet_info, new_ratchet_info)

    def test_fetch_ratchet_by_session_id(self):
        new_session_id = b"\xce\x82\x1f\x9e\x1b\x8e\xee\xfc\xe5\xa6\x88\xac\x7f\xa1\x06\xf8\x8a`K<\x83\x956'\xc3L\xee\x13\xc5\x04(\x8f"
        new_peer_id = b'\xb2\xfe\'j\x9b\x8e}\xb3^\x99\xe8A!\xaf\xa2H\x0b\xfd\x1e\xe8\xaa\x0f\xf9\xd7\x98\xbe\x1f\xca\x96]"A'
        new_ratchet_info = "jsonencodedratchet"
        cur = self.client_storage.cursor().cursor
        cur.execute("INSERT INTO ratchetstorage VALUES (?, ?, ?)",
                    (utils.encode_64(new_session_id), utils.encode_64(new_peer_id), new_ratchet_info))

        fetched_ratchet = self.keystorage.fetch_ratchet_by_session_id(new_session_id)
        self.assertTrue(fetched_ratchet is not None)

        session_id, peer_id, ratchet_info = fetched_ratchet
        self.assertEqual(session_id, new_session_id)
        self.assertEqual(peer_id, new_peer_id)
        self.assertEqual(ratchet_info, new_ratchet_info)

    def test_fetch_ratchet_by_peer_id(self):
        new_session_id = b"\xce\x82\x1f\x9e\x1b\x8e\xee\xfc\xe5\xa6\x88\xac\x7f\xa1\x06\xf8\x8a`K<\x83\x956'\xc3L\xee\x13\xc5\x04(\x8f"
        new_peer_id = b'\xb2\xfe\'j\x9b\x8e}\xb3^\x99\xe8A!\xaf\xa2H\x0b\xfd\x1e\xe8\xaa\x0f\xf9\xd7\x98\xbe\x1f\xca\x96]"A'
        new_ratchet_info = "jsonencodedratchet"
        cur = self.client_storage.cursor().cursor
        cur.execute("INSERT INTO ratchetstorage VALUES (?, ?, ?)",
                    (utils.encode_64(new_session_id), utils.encode_64(new_peer_id), new_ratchet_info))

        fetched_ratchet = self.keystorage.fetch_ratchet_by_peer_id(new_peer_id)
        self.assertTrue(fetched_ratchet is not None)

        session_id, peer_id, ratchet_info = fetched_ratchet
        self.assertEqual(session_id, new_session_id)
        self.assertEqual(peer_id, new_peer_id)
        self.assertEqual(ratchet_info, new_ratchet_info)

    def test_update_ratchet(self):
        new_session_id = b"\xce\x82\x1f\x9e\x1b\x8e\xee\xfc\xe5\xa6\x88\xac\x7f\xa1\x06\xf8\x8a`K<\x83\x956'\xc3L\xee\x13\xc5\x04(\x8f"
        new_peer_id = b'\xb2\xfe\'j\x9b\x8e}\xb3^\x99\xe8A!\xaf\xa2H\x0b\xfd\x1e\xe8\xaa\x0f\xf9\xd7\x98\xbe\x1f\xca\x96]"A'
        new_ratchet_info = "jsonencodedratchet"
        cur = self.client_storage.cursor().cursor
        cur.execute("INSERT INTO ratchetstorage VALUES (?, ?, ?)",
                    (utils.encode_64(new_session_id), utils.encode_64(new_peer_id), new_ratchet_info))

        self.keystorage.update_ratchet(new_session_id, "updatedjsonencodedratchet")

        cur.execute("SELECT ratchet_info FROM ratchetstorage WHERE session_id=:encoded_id",
                    {"encoded_id": utils.encode_64(new_session_id)})

        ratchet_info = cur.fetchall()
        self.assertEqual(ratchet_info[0][0], "updatedjsonencodedratchet")


    def test_delete_session(self):
        new_session_id = b"\xce\x82\x1f\x9e\x1b\x8e\xee\xfc\xe5\xa6\x88\xac\x7f\xa1\x06\xf8\x8a`K<\x83\x956'\xc3L\xee\x13\xc5\x04(\x8f"
        new_peer_id = b'\xb2\xfe\'j\x9b\x8e}\xb3^\x99\xe8A!\xaf\xa2H\x0b\xfd\x1e\xe8\xaa\x0f\xf9\xd7\x98\xbe\x1f\xca\x96]"A'
        new_ratchet_info = "jsonencodedratchet"
        cur = self.client_storage.cursor().cursor
        cur.execute("INSERT INTO ratchetstorage VALUES (?, ?, ?)",
                    (utils.encode_64(new_session_id), utils.encode_64(new_peer_id), new_ratchet_info))

        self.keystorage.delete_session(new_session_id)
        cur.execute("SELECT * from ratchetstorage")

        fetched_ratchets = cur.fetchall()
        self.assertTrue(len(fetched_ratchets) == 0)






