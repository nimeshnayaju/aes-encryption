import socket
import os
import threading
import hashlib
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
import signal

def remove_padding(s):
  return s.replace("`", "")

def padding(s):
  return s + ((16 - len(s) % 16) * "`")

def receive_message():
  while True:
    emsg = server.recv(1024)
    msg = remove_padding(AESKey.decrypt(emsg))
    if msg == FLAG_QUIT:
      print("Server was shut down by admin")
      os.kill(os.getpid(), signal.SIGKILL)
    else:
      print("Server's encrypted message: " + emsg)
      print("Server said: " + msg)

def send_message():
  while True:
    msg = raw_input("[>] YOUR MESSAGE : ")
    en = AESKey.encrypt(padding(msg))
    server.send(str(en))
    if msg == FLAG_QUIT:
      os.kill(os.getpid(), signal.SIGKILL)
    else:
      print("Your encrypted message: " + en)

if __name__ == "__main__":
  server = ""
  AESKey = ""
  FLAG_READY = "Ready"
  FLAG_QUIT = "quit"

  random = Random.new().read
  # Create a private key of size 1024 by generating random characters
  RSAkey = RSA.generate(1024, random)
  # Generate RSA public key
  public = RSAkey.publickey().exportKey()
  # Generate RSA private key
  private = RSAkey.exportKey()
  # Hash the public key to send over to server, using md5 hash 
  tmpPub = hashlib.md5(public)
  my_hash_public = tmpPub.hexdigest()

  print(public)
  print("\n", private)
  
  host = raw_input("Host : ")
  port = int(input("Port: "))

  with open("private.txt", "w"):
    pass
  with open("public.txt", "w"):
    pass
  
  try:
    file = open("private.txt", "w")
    file.write(private)
    file.close()

    file = open("public.txt", "w")
    file.write(public)
    file.close()

  except BaseException:
    print("Failed to store key")
  
  check = False

  try:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host, port))
    check = True
  except BaseException:
    print("Check server address or port")
  
  if check:
    print("Connection successful")
    # Sends public key and public key hash to server
    server.send(public + ":" + my_hash_public)
    # receive public key, hash of pubilc key, eight byte and hash of eight byte from server
    fGet = server.recv(4072)
    split = fGet.split(":")
    # Encrypted eight byte session key, hash of session key and hash of public key
    toDecrypt = split[0]
    # public key of server
    serverPublic = split[1]
    print("Server's public key: " + serverPublic)
    # decrypt the keys
    decrypted = RSA.importKey(private).decrypt(eval(toDecrypt.replace("\r", '\\r').replace('\n','\\n')))
    splittedDecrypt = decrypted.split(":")
    eightByte = splittedDecrypt[0]
    hashOfEight = splittedDecrypt[1]
    hashOfSPublic = splittedDecrypt[2]
    print("Client's eight byte key in hash" + hashOfEight)
  
    # Hash eight byte session key for integrity checking
    sess = hashlib.md5(eightByte)    
    session = sess.hexdigest()

    # Hash public key of server for integrity checking
    hashObj = hashlib.md5(serverPublic)
    server_public_hash = hashObj.hexdigest()

    print("Comparing server's public key and eight byte key\n")
    if (server_public_hash == hashOfSPublic and session == hashOfEight):
      #encrypt back the eight byte key with the server's public key and send it to server
      print("Sending encrpyted session key\n")
      serverPublic = RSA.importKey(serverPublic).encrypt(eightByte, None)
      server.send(str(serverPublic))

      # Create 128 bits key with 16 bytes
      print("Creating AES key")
      key_128 = eightByte + eightByte[::-1]
      AESKey = AES.new(key_128, AES.MODE_CBC, IV=key_128)

      # Ready for receiving
      serverMsg = server.recv(2048)
      # Decrypt message received from server using the 128 bits AES key created using session key
      serverMsg = remove_padding(AESKey.decrypt(serverMsg))

      if(serverMsg == FLAG_READY):
        print("Server is ready to communicate\n")
        serverMsg = raw_input("\n[>] ENTER YOUR NAME : ")
        server.send(serverMsg)
        threading_rec = threading.Thread(target=receive_message)
        threading_rec.start()
        threading_send = threading.Thread(target=send_message)
        threading_send.start()
    else:
      print("(Public key && Public key hash) || (Session key && Hash of Session key) doesn't match")




