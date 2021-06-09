from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, DES
import struct as st
import argparse
import os
from argparse import RawTextHelpFormatter
import hashlib
from io import StringIO
import json
from flask import Flask, request
import base64
from contextlib import contextmanager
from torpy.http.requests import TorRequests
from requests import Request
from urllib3.util import SKIP_HEADER
import logging

# stop flask log


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# setting max file size to 4 GB or (4 * 1024 * 1024 * 1024) Bytes


MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024
RETRIES = 10

# Create A flask app for client
app = Flask("filecrypter")


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


# File Sender Helper
@contextmanager
def tor_requests_session(hops_count=3, headers=None, auth_data=None, retries=0):
    with TorRequests(hops_count, headers, auth_data) as tr:
        with tr.get_session(retries=retries) as s:
            yield s


def do_request(url, method='GET', data=None, headers=None, hops=3, auth_data=None, retries=0):
    with tor_requests_session(hops, auth_data, retries=retries) as s:
        headers = dict(headers or [])
        if SKIP_HEADER and \
                'user-agent' not in (k.lower() for k in headers.keys()):
            headers['User-Agent'] = SKIP_HEADER
        response = Request(method, url, data=data, headers=headers)
        response = s.send(response.prepare(), verify=False)
        return response.text


def send(link, data, retry_number=15, num_hops=4):
    json_formatted_data = json.dumps({
        'file': str(base64.b64encode(data))[2:-1],
        'hash': hashlib.md5(data).hexdigest()
    })
    payload = {'data': json_formatted_data}
    return do_request(link, method='POST', data=payload, retries=retry_number, hops=num_hops)


# Function to Send the Data over Hidden Network


def send_file(link, filename, circuit_no=3):
    file_to_send = open(filename, 'rb').read()
    response = send(link + '/post', file_to_send, retry_number=15, num_hops=circuit_no)
    io = StringIO(response)
    print("[*] File Sent, Checking Hash....")
    receiver_file_hash = json.load(io)['hash']
    sender_file_hash = hashlib.md5(file_to_send).hexdigest()
    print('[*] Sent File Hash: {}'.format(sender_file_hash))
    print('[*] Receiver File Hash: {}'.format(receiver_file_hash))
    if receiver_file_hash == sender_file_hash:
        print('[*] File Sent Successfully. ')
    else:
        print('[*] Please Resent The Data. ')


# Function to receive the data

def client_program(port=443, outfile=None):
    if outfile is None:
        outfile = "data.file"

    @app.route('/post', methods=['POST'])
    def get_file():
        if request.method == 'POST':
            print('[*] Receive Request From IP: {}'.format(request.remote_addr))
            data = StringIO(request.form['data'])
            data = json.load(data)
            file_hash = data['hash']
            downloaded_file = base64.b64decode(data['file'])
            downloaded_file_hash = hashlib.md5(downloaded_file).hexdigest()
            print("[*] File Hash: {}".format(file_hash))
            print("[*] Received File Hash: {}".format(downloaded_file_hash))
            if downloaded_file_hash == file_hash:
                print("[*] File Received Successfully")
                print("[*] File is written to {}".format(os.path.abspath("./" + outfile)))
                file_to_write = open(outfile, 'wb+')
                file_to_write.write(downloaded_file)
                file_to_write.close()
            else:
                print("File Hash Not Matched. Trying to Receive Again Don't Close The Program")
            return json.dumps({"hash": downloaded_file_hash})

    app.run(debug=False, host='0.0.0.0', port=port, ssl_context='adhoc')


# Create a Method to Parse Options by Argument


def main():
    parser = argparse.ArgumentParser("filecryptor",
                                     description=('Description: Script to Help Encrypt and Decrypt File Using RSA Key.'
                                                  '\n\n'
                                                  '\tpython -m filecryptor --m enc --file=test.txt --key=pub.key\n'
                                                  '\tpython -m filecryptor --m dec --file=test.txt.enc --key=private.key\n'
                                                  '\tpython -m filecryptor --m gen --keySize=2048\n\n'

                                                  'Send File Via Hidden Network: \n'
                                                  'Link Needs to be Starts With [https://]\n'
                                                  '\tpython -m filecrypter --m send --file test.txt --link https://[HOST_IP]:443 --c 4'
                                                  '\n'


                                                  'Create a Client to Receive From a Network:\n'
                                                  '\tpython -m filecryptor --m client --port 443 --file to_file\n\n\n'
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
    parser.add_argument("--link", help="Link to send file", type=str)
    parser.add_argument("--port", help="Port to start the client Default(443)", type=str)
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
        if not args.file or not args.link or args.port:
            print('Need --file and --link to send data use port with link as below:\nhttps://[HOST_IP]:443')
        else:
            if not args.c:
                send_file(args.link, args.file)
            else:
                send_file(args.link, args.file, args.c)
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
        print("Please Run 'python -m filecryptor --help' to Check Commands")


if __name__ == '__main__':
    main()
