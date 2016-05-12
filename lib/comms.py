import struct

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import XOR
from Crypto.Hash import HMAC
from Crypto import Random
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=True):
        self.conn = conn
        self.iv = 0
        self.enc = False
        self.shared_key = 0
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_key = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_key))

        # Enables encryption
        self.enc = True

    def send(self, data):
        if self.enc:
            #Convert shared_key to bytes
            #key = bytes(self.shared_key[:32],"ascii")
            hmac = HMAC.new(self.shared_key[:32],data).digest()
            #Padding the message
            data_pad = ANSI_X923_pad(data, AES.block_size)
            
            #Generate a iv and create a new cipher for each msg
            iv = bytes(str(Random.new().read( AES.block_size)), "ascii")[:16]
            self.cipher = AES.new(self.shared_key[:32], AES.MODE_CBC, iv)

            #Encrypt the message
            ciphertext_pad = self.cipher.encrypt(data_pad)

            #Concatenate the iv and ciphertext
            encrypted_data = iv + hmac + ciphertext_pad
            
            if self.verbose:
                print("-------------------------------Sending-------------------------------")
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
                print("--------------------------------Sent---------------------------------")
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)
        

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        #print("Encrypted data: {}".format(repr(encrypted_data)))
        if self.enc:
            # The first 16 bytes of message is the iv
            iv = encrypted_data[:16]

            #HMAC
            rec_hmac = encrypted_data[16:32]
            #ciphertext is the message after 16 bytes
            ciphertext_pad = encrypted_data[32:]

            #Generate a new cipher for decryption
            self.cipher = AES.new(self.shared_key[:32],AES.MODE_CBC,iv)

            #Decrypt text
            plaintext_pad = self.cipher.decrypt(ciphertext_pad)

            #Unpad plaintext
            plaintext = ANSI_X923_unpad(plaintext_pad, DES.block_size)

            #Comparing HMAC 
            hmac = HMAC.new(self.shared_key[:32],plaintext).digest()
            print("-------------------------------Checking integrity-------------------------------")
            if(rec_hmac == hmac):
                print("Message was not modified")
            else:
                print("Message was modified be careful")
            print("------------------------------Integrity Checked--------------------------------")
            
            if self.verbose:
                print("------------------------------Decrypting data-------------------------------")
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(plaintext))
                print("-------------------------------Data Decrypted--------------------------------")
        else:
            plaintext = encrypted_data
            
               

        return plaintext

    def close(self):
        self.conn.close()
