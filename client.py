import socket
import os
import random
# host = socket.gethostbyname('LAPTOP-NCLJ4M38') #siddiqul
# host = socket.gethostbyname('LAPTOP-LLHFBHBJ') #musharraf
# host = socket.gethostbyname('LAPTOP-EHJ8VBPC') #musharraf

host = '127.0.0.1'
port = 23000
ADDR = (host, port)
SIZE = 1024
DISCONNNECT_PROTOCOL = "disconnect"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

print("Client is conected")

def replaceWords(conn):
    replacing = True
    msg = conn.recv(SIZE).decode()
    print(msg)
    myMsg = input("Enter Your Msg: ")
    while replacing:
        conn.send(myMsg.encode())
        msg = conn.recv(SIZE).decode()
        data = input(f"{msg}: ")
        conn.send(data.encode())
        if(data == "_exit"):
            replacing = False
            break

        msg = conn.recv(SIZE).decode()
        data = input(f"{msg}: ")
        conn.send(data.encode())
        myMsg = conn.recv(SIZE).decode()
        print("[SERVER]: ",myMsg)


# files = os.listdir('./files')
def diffie_hellman_client(conn):
    p=23
    g=5
    # private_key = int(input("Enter Private key : "))
    private_key = 17
    public_key = (g ** private_key) % p
    conn.send(str(public_key).encode())
    server_public_key = int(conn.recv(SIZE).decode())
    shared_secret = (server_public_key ** private_key) % p
    return shared_secret

def custom_encrypt(message,conn):
    key = diffie_hellman_client(conn)
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shift = key % 26  
            if char.islower():
                encrypted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            else:
                encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
        else:
            encrypted_char = char  
        encrypted_message += encrypted_char
    return encrypted_message

def sendFiles():
    msg = client.recv(SIZE).decode()
    print(msg)
    data = input("Enter File Path : ")
    pth = os.path.abspath(data)
    files = os.listdir(pth)

    for file in files:
        client.send(file.encode())
        msg = client.recv(SIZE).decode()
        if(msg == "__TEXT__"):
            with open(f"{pth}/{file}") as f:
                msg = f.read()
                if not msg:
                    msg = " "
                client.send(msg.encode())
    
    msg = "__SENT__" 
    client.send(msg.encode())
    msg = client.recv(SIZE).decode()
    print(msg)

def sendName():
    nameSent = False
    while not nameSent:
        data = input("Enter Unique Name: ");
        client.send(data.encode())
        msg = client.recv(SIZE).decode()
        if msg == f"{data} Name Received":
            nameSent = True
        print(msg)

def sendClient():
    msg = ""
    # Sending another Client name to Connect
    data = input("Enter Client Name: ")
    client.send(data.encode())
    msg = client.recv(SIZE).decode()
    clientName = data
    print(msg)
    if(msg == "No Client Found"):
        return
    
    clientConnection = True
    while clientConnection:
        data = input(f"Enter Your Msg to {clientName}: ")
        client.send(data.encode())
        if(data == DISCONNNECT_PROTOCOL):
            clientConnection = False
        msg = client.recv(SIZE).decode()
        print(msg)
    return

def main():
    connected = True
    print("Client = ", client)
    # SENDING NAME
    sendName()
    # NAME SENT
    

    while connected:
        # shared_secret = diffie_hellman_client(client)
        data = input("Enter Msg : ")
        # encrypted_data=custom_encrypt(data,5)
        encrypted_data=custom_encrypt(data,client)

        # client.send(data.encode())
        client.send(encrypted_data.encode())
        # shared_secret = diffie_hellman_client(client)
        if (data == "countFiles()"):
            sendFiles()
        
        elif (data == "sendMsg()"):
            sendClient()

        elif (data == "disconnect"):
            msg = client.recv(SIZE).decode()
            print(msg)
            client.close()
            connected = False
        
        elif (data == "getMsg()") :
            msg = client.recv(SIZE).decode()
            print(msg)

        elif (data == "replaceWords()") :
            replaceWords(client)
        else:
            # print("Waiting for server...")
            msg = client.recv(SIZE).decode()
            print(msg)

if __name__ == "__main__" :
    main()