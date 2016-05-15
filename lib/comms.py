import struct
from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Cipher import XOR, AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad, AES256_CBC_Encrypt, AES256_CBC_Decrypt 
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=True):
        self.conn = conn
        self.enc = False
        self.shared_key = 0
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()
        self.last_token = 0
        self.current_token = 0
        self.session_token = 0
        self.token_send = 0
        self.token_recv = 0

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
            #Creating session_token
            self.token_send += len(data)

            #Appending session token in data
            data = b64encode(self.token_send.to_bytes(4, 'little')) + data
            #Return ciphertext and iv used to encrypt it.
            ciphertext_pad,iv = AES256_CBC_Encrypt(self.shared_key[:32],data)

            #Creating HMAC
            hmac = HMAC.new(self.shared_key[:32],digestmod=SHA256)
            hmac.update(ciphertext_pad)
             
            #Concatenate the iv hmac and ciphertext
            encrypted_data = iv + bytes(hmac.hexdigest(),"ascii") + ciphertext_pad
            
            if self.verbose:
                print("-------------------------------Sending-------------------------------")
                print("Original data: {}".format(data[8:]))
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

            #HMAC 64 bytes
            rec_hmac = encrypted_data[16:80]

            #Data
            ciphertext = encrypted_data[80:]

            #Comparing HMAC 
            hmac = HMAC.new(self.shared_key[:32],digestmod=SHA256)
            hmac.update(ciphertext) 
            hmac = bytes(hmac.hexdigest(),"ascii")
            
            
            print("-------------------------------Checking integrity-------------------------------")
            if(rec_hmac == hmac):
                print("Message was not modified")
               
            else:
                print("Message was modified and discarted")
            print("------------------------------Integrity Checked--------------------------------")
                
            #Decrypt text
            plaintext = AES256_CBC_Decrypt(self.shared_key[:32], iv, ciphertext)

            #Look session id
            token_recv = int.from_bytes(b64decode(plaintext[:8]), 'little')
            
            #Separates id and plaintext
            plaintext = plaintext[8:]
            
            #Computing session id
            self.token_recv += len(plaintext)

            print("-------------------------------Checking session-------------------------------")
            if self.token_recv == token_recv:
                print("Valid session token")
            else:
                print("Invalid session token be careful replay attack")
            print("-------------------------------Session checked--------------------------------")

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
