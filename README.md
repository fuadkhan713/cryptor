<pre>
<b>Install:</b>
    pip install filecrypter

usage: python -m filecrypter [-h] [--m {enc,dec,gen,send,client}] [--file FILE] [--key KEY] [--keySize {512,1024,2048,4096}] [--host HOST] [--port PORT] [--c C]

Description: Script to Help Encrypt and Decrypt File Using RSA Key.

        python -m filecrypter --m enc --file=test.txt --key=pub.key
        python -m filecrypter --m dec --file=test.txt.enc --key=private.key
        python -m filecrypter --m gen --keySize=2048

Send File Via Hidden Network:
        python -m filecrypter --m send --file test.txt --host google.com --port 443
Create a Client to Receive From a Network:
        python -m filecrypter --m client --port 443 --file to_file

IMPORTANT NOTES AND BUGS:
        1. MAIN FILE WILL BE DELETED AFTER ENCRYPTION.
        2. ENCRYPTED FILE WILL BE DELETED AFTER DECRYPTION.
        3. MAXIMUM FILE SIZE IS 4GB. THIS LIMIT ALSO DEPENDS ON SYSTEM RAM.
           MIGHT NOT WORK WITH LESS RAM. DONT WORRY FILE WONT BE DELETED IF FAILED.

optional arguments:
  -h, --help            show this help message and exit
  --m {enc,dec,gen,send,client}
                        Mode for operation [enc]/[dec]/[gen]/[send]/[client]
  --file FILE           File to encrypt/decrypt
  --key KEY             Key to encrypt/decrypt
  --keySize {512,1024,2048,4096}
                        Key size default is 2048 bit
  --host HOST           Host to send file
  --port PORT           Port to remote host
  --c C                 Num of tor circuit to create While sending file Default(3)


</pre>