from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, DES
import struct as st
import argparse
import os
from argparse import RawTextHelpFormatter
from torpy import TorClient
import socket
import hashlib

# setting max file size to 4 GB or (4 * 1024 * 1024 * 1024) Bytes


MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024


def gen_key(key_size=2048):
    """
        1. Create key with key_size and random number function
        2. Save the key to a file
        :param key_size: default is 2048
        :return: none
    """
    random_func = Random.new().read
    key = RSA.generate(key_size, random_func)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Now trying to write the public key and private key to file
    try:
        private_file = open("private.key", "wb+")
        pub_file = open("pub.key", "wb+")
        private_file.write(private_key)
        pub_file.write(public_key)
        print("""[*] DONE""")
        private_file.close()
        pub_file.close()
    except Exception as e:
        print(e)

    # print private and public key to the console
    print(private_key.decode('utf8'))
    print(public_key.decode('utf8'))
    print("""[*] Written To file.......... "{}" and "{}" """.format(os.path.abspath("private.key"),
                                                                    os.path.abspath("pub.key")))


# Helper functions for encryption process


def check_file_with_padding_add_for_enc(file_to_encrypt):
    if len(file_to_encrypt) > MAX_FILE_SIZE:
        print("[*] MAX FILE SIZE is 4GB")
        exit()

    if len(file_to_encrypt) == 0:
        print("[*] Input file to encrypt is empty. Ignoring....")
        exit()
    if len(file_to_encrypt) % 16 != 0:
        file_to_encrypt = st.pack("I", len(file_to_encrypt)) + file_to_encrypt + b" " * (
                16 - ((len(file_to_encrypt) % 16) - 4))
    return file_to_encrypt


# Function for encryption Process


def encrypt_data(filename, key):
    """
    :param filename: file name/ file name with path to encrypt
    :param key: key(private/public) file to encrypt or decrypt the data
    :return: None
    """
    ecb_key = Random.new().read(8)
    des_cipher = DES.new(ecb_key, DES.MODE_ECB)
    public_key = RSA.import_key(open(key, 'r').read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    try:
        file_to_encrypt = open(filename, 'rb').read()
        file_to_encrypt = check_file_with_padding_add_for_enc(file_to_encrypt)
        enc_file = open(filename + ".enc", "wb+")

        en_c_data = des_cipher.encrypt(file_to_encrypt)
        del file_to_encrypt
        print("[*] Encrypting File .....")
        ecb_key = cipher_rsa.encrypt(ecb_key)
        en_c_data = ecb_key + en_c_data

        enc_file.write(en_c_data)
        enc_file.close()
        print("File encrypted as: {}".format(os.path.abspath(filename + ".enc")))
        os.remove(filename)
    except Exception as e:
        print(e)
        exit()


# Helper function for decryption process
def check_file_for_dec(filename, enc_file):
    if ''.join(filename[-4:]) != ".enc":
        print("Filename Must End with '.enc'")
        exit()
    if len(enc_file) == 0:
        print("[*] Input file to encrypt is Empty. Ignoring.........")
        exit()


# Function to Decrypt the data

def decrypt_data(filename, key):
    """
    :param filename: Filename to Decrypt
    :param key: Private key file name for Decryption Process
    :return: None
    """
    private_key = RSA.import_key(open(key, 'r').read())
    rsa_cipher = PKCS1_OAEP.new(private_key)

    key_size = private_key.size_in_bytes()
    try:

        enc_file = open(filename, 'rb').read()
        check_file_for_dec(filename, enc_file)
        ecb_key_encrypted = enc_file[:key_size]
        enc_file = enc_file[key_size:]
        des_key = rsa_cipher.decrypt(ecb_key_encrypted)
        des_cipher = DES.new(des_key, DES.MODE_ECB)
        print("[*] Decrypting File......")
        dec_file = des_cipher.decrypt(enc_file)
        del enc_file
        file_name_split = filename.split(".")[:-1]

        size = st.unpack("<I", dec_file[:4])[0]

        dec_file = dec_file[4:size + 4]

        open('.'.join(file_name_split), 'wb+').write(dec_file)
        print("[*] File Decrypted as: {}".format(os.path.abspath('.'.join(file_name_split))))
        os.remove(filename)
    except Exception as e:
        print(e)


# Function to Send the Data over Hidden Network


def send_file(host, port, filename, circuit_no=3):
    file_to_send = open(filename, 'rb').read()
    print("[*] Sending File with File md5 {}: ".format(bytes(hashlib.md5(file_to_send).hexdigest(), 'utf8')))

    print("[*] Please wait. Trying to send....")
    try:
        with TorClient() as tor:
            with tor.create_circuit(circuit_no) as circuit:
                with circuit.create_stream((host, port)) as stream:
                    # Now we can try to communicate with host
                    stream.send(b'' + file_to_send + bytes(hashlib.md5(file_to_send).hexdigest(), 'utf8'))
                    while True:
                        recv_hash = stream.recv(32)
                        print(recv_hash)
                        if 32 == len(recv_hash):
                            break
                    print(bytes(hashlib.md5(file_to_send).hexdigest()))
                    print(recv_hash)
        if hash == bytes(hashlib.md5(file_to_send).hexdigest(), 'utf8'):
            print("[*] Data Sent")
        else:
            print("[*] Trying to send the data again. Enter Ctrl+C to Exit.")
            send_file(host, port, filename)
    except Exception as e:
        print(e)
        print("[*] Trying to send the data again. Enter Ctrl+C to Exit.")
        send_file(host, port, filename)


# Function to receive the data

def client_program(port=5000, outfile=None):
    if outfile is None:
        outfile = "data.file"
    host = '0.0.0.0'
    server_socket = socket.socket()
    server_socket.bind((host, int(port)))
    server_socket.listen(500)
    data_to_file = b''
    print("[*] Client Started as {}:{}".format(host, port))
    print("[*] Receiving File...")
    conn, address = server_socket.accept()
    print("[*] Connection from: " + str(address))
    while True:
        data = conn.recv(1024)
        data_to_file = data_to_file + data
        if not data:
            print("[*] Checking Received File HASH")
            print("[*] File Hash: {}".format(data_to_file[-32:]))
            print("[*] Received File Hash: {}".format(bytes(hashlib.md5(data_to_file[:-32]).hexdigest(), 'utf8')))
            if data_to_file[-32:] == bytes(hashlib.md5(data_to_file[:-32]).hexdigest(), 'utf8'):
                print("[*] Hash Matched")
                file_to_write = open("data.file", 'wb+')
                file_to_write.write(data_to_file[:-32])
                file_to_write.close()
                print("[*] File Received Successfully")
                print("[*] File is written to {}".format(os.path.abspath("./" + outfile)))
                conn.send(data_to_file[-32:])
                conn.close()
                break
            else:
                conn.close()
                conn, address = server_socket.accept()
                print("[*] File Not Received Properly. Trying to Receive Again..Please wait")
                print("[*] Connection from: " + str(address))
                print("[*] Receiving File...")
                data_to_file = b''


# Create a Method to Parse Options by Argument


parser = argparse.ArgumentParser("cryptor.py",
                                 description=('Description: Script to Help Encrypt and Decrypt File Using RSA Key.'
                                              '\n\n'
                                              '\tpython3 cryptor.py --m enc --file=test.txt --key=pub.key\n'
                                              '\tpython3 cryptor.py --m dec --file=test.txt.enc --key=private.key\n'
                                              '\tpython3 cryptor.py --m gen --keySize=2048\n\n'

                                              'Send File Via Hidden Network: \n'
                                              '\tpython3 cryptor.py --m send --file test.txt --host google.com --port '
                                              '80\n'


                                              'Create a Client to Receive From a Network:\n'
                                              '\tpython3 cryptor.py --m client --port 5000 --file to_file\n\n\n'
                                              'IMPORTANT NOTES AND BUGS:\n'
                                              '\t1. MAIN FILE WILL BE DELETED AFTER ENCRYPTION.\n'
                                              '\t2. ENCRYPTED FILE WILL BE DELETED AFTER DECRYPTION.\n'
                                              '\t3. MAXIMUM FILE SIZE IS 4GB. THIS LIMIT ALSO DEPENDS ON SYSTEM RAM.'
                                              '\n\t   MIGHT NOT WORK WITH LESS RAM. DONT WORRY FILE WONT '
                                              'BE DELETED IF FAILED.'
                                              '\n\n'), formatter_class=RawTextHelpFormatter)
parser.add_argument("--m", help="Mode for operation [enc]/[dec]/[gen]/[send]/[client]", type=str,
                    choices=['enc', 'dec', 'gen', 'send', 'client'])
parser.add_argument("--file", help="File to encrypt/decrypt", type=str)
parser.add_argument("--key", help="Key to encrypt/decrypt", type=str)
parser.add_argument("--keySize", help="Key size default is 2048 bit", type=int, choices=[512, 1024, 2048, 4096],
                    default=2048)
parser.add_argument("--host", help="Host to send file", type=str)
parser.add_argument("--port", help="Port to remote host ", type=str)
parser.add_argument("--c", help="Num of tor circuit to create While sending file Default(3)", type=int)

args = parser.parse_args()
if args.m == 'enc':
    if not args.file or not args.key:
        print('Need --file and --key args for encrypt data')
    else:
        encrypt_data(args.file, args.key)
elif args.m == 'dec':
    if not args.file or not args.key:
        print('Need --file and --key args for decrypt data')
    else:
        decrypt_data(args.file, args.key)
elif args.m == 'gen':
    if not args.keySize:
        print("""Generating 2048 bit 'private.key' and 'pub.key' File """)
        gen_key()
    else:

        gen_key(args.keySize)
elif args.m == 'send':
    if not args.file or not args.host or not args.port:
        print('Need --file and --host and --port to send data')
    else:
        if not args.c:
            send_file(args.host, args.port, args.file)
        else:
            send_file(args.host, args.port, args.file, args.c)
elif args.m == 'client':
    if not args.port and args.file:
        client_program(outfile=args.file)
    elif args.port and not args.file:
        client_program(port=args.port)
    elif args.port and args.file:
        client_program(port=args.port, outfile=args.file)
    else:
        client_program()
else:
    print("Please Run 'python3 crypto.py --help' to Check Commands")
