import socket
import os
import signal
import threading
import hashlib
import struct
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA

def remove_padding(s):
  return s.replace("`", "")

def padding(s):
  return s + ((16 - len(s) % 16) * "`")

def connection_setup():
  while True:
    if check:
      client, address = server.accept()
      print("A client is trying to connect")
      # Get client's public key and public key hash
      clientPH = client.recv(2048)
      split = clientPH.split(":")
      # Public key of client
      tmpClientPublic = split[0]
      # Hash of public key of client
      clientPublicHash = split[1]
      print("Anonymous client's public key " + tmpClientPublic)
      tmpClientPublic = tmpClientPublic.replace("\r\n", "")
      clientPublicHash = clientPublicHash.replace("\r\n", "")
      # Hash the public key of client
      tmpHashObject = hashlib.md5(tmpClientPublic)
      tmpHash = tmpHashObject.hexdigest()

      # Check if the hash generated is equal to the hash of public key received from client
      if tmpHash == clientPublicHash:
        # Send public key, encrypted eight byte, hash of eight byte and server's public key hash
        print("Anonymous client's public key and public key hash matched")
        clientPublic = RSA.importKey(tmpClientPublic)
        fSend = eightByte + ":" + session + ":" + my_hash_public
        fSend = clientPublic.encrypt(fSend, None)
        client.send(str(fSend) + ":" + public)

        clientPH = client.recv(2048)
        if clientPH != "":
          # Decrypt message (encrypted session key) received from client using server's private key
          clientPH = RSA.importKey(private).decrypt(eval(clientPH.decode('utf-8')))
          print("Matching session key")
          # Check if the session key decrypted from hash of session key sent from client matches the session key stored at server
          if clientPH == eightByte:
            # Create 128 bits key with 16 bytes
            print("Creating AES key")
            key_128 = eightByte + eightByte[::-1]
            AESKey = AES.new(key_128, AES.MODE_CBC, IV=key_128)
            # Encrypt the FLAG_READY message using the 128 bits AES key
            clientMsg = AESKey.encrypt(padding(FLAG_READY))
            # Send the encrypted message to client
            client.send(clientMsg)

            print("Waiting for client's name")
            clientMsg = client.recv(2048)
            CONNECTION_LIST.append((clientMsg, client))
            print("\n" + clientMsg + " IS CONNECTED")
            # Use multi threading so that the chat can be done in real time
            threading_client = threading.Thread(target=broadcast_usr, args=[clientMsg, client, AESKey])
            threading_client.start()
            threading_message = threading.Thread(target=send_message, args=[client, AESKey])
            threading_message.start()
          else:
            print("\n Session key from client did not match")
      else:
        print("Public key and public hash did not match")
        client.close()
  
def send_message(socketClient, AESk):
  while True:
    msg = raw_input("\n[>] ENTER YOUR MESSAGE : ")
    en = AESk.encrypt(padding(msg))
    socketClient.send(str(en))
    if msg == FLAG_QUIT:
        os.kill(os.getpid(), signal.SIGKILL)
    else:
        print("\n[!] Your encrypted message \n" + en)

def broadcast_usr(uname, socketClient, AESk):
  while True:
    try:
      data = socketClient.recv(1024)
      en = data
      if data:
        data = remove_padding(AESk.decrypt(data))
        if data == FLAG_QUIT:
          print("\n" + uname + " left the conversation")
        else:
          b_usr(socketClient, uname, data)
          print("\n", uname, " SAID:" , data)
          print("\n[!] Client's encrypted message\n" + en)
    except Exception as x:
      print(x.message)
      break

def b_usr(cs_sock, sen_name, msg):
  for client in CONNECTION_LIST:
    if(client[1] != cs_sock):
      client[1].send(sen_name)
      client[1].send(msg)


if(__name__ == "__main__"):
  host = ""
  port = 0
  server = ""
  AESKey = ""
  CONNECTION_LIST = []
  FLAG_READY = "Ready"
  FLAG_QUIT = "quit"
  YES = "1"
  NO = "2"

  random = Random.new().read
  RSAkey = RSA.generate(1024, random)
  public = RSAkey.publickey().exportKey()
  private = RSAkey.exportKey()

  tmpPub = hashlib.md5(public)
  my_hash_public = tmpPub.hexdigest()

  eightByte = os.urandom(8)
  sess = hashlib.md5(eightByte)
  session = sess.hexdigest()

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
  print("[1] Auto connect with braodcast IP & PORT\n[2] Manually enter IP & PORT\n")
  ask = raw_input("[>] ")
  if ask == YES:
    host = "127.0.0.1"
    port = 8080
  elif ask == NO:
    host = input("Host: ")
    port = int(input("Port: "))
  else:
    print("[!] Invalid selection")
    os.kill(os.getpid(), signal.SIGKILL) #SIGTERM 

  print("\n",public,"\n\n",private)
  print("Eight byte session key in hash: " + session)
  print("Server IP: " + host + " & PORT: " + str(port))

  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  server.bind((host, port))
  server.listen(1)
  print("\n [!] Successfully connected to server")
  check = True
  # Accept clients
  threading_accept = threading.Thread(target=connection_setup)
  threading_accept.start()



      

