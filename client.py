# Python3
# Zhaoyan Liu
# coding: utf-8

import json
import atexit
import threading
import time
import sys
from socket import *
from typing import Dict, List

if len(sys.argv) != 2:
    print("Usage: python client.py server_port")
    exit(0)
server_name = "localhost"
server_port = int(sys.argv[1])

stop_process = False

# get the thread
condition = threading.Condition()

# map of username to private tcp socket
private_user_sockets: Dict = dict()

# stop the process
def stop():
    global Socket, private_socket
    Socket.send(json.dumps({"command": "logout"}).encode())
    Socket.close()

def check_login():
    global Socket, client_username, message, private_socket
    Socket.send(message.encode())
    # get the login response
    response = Socket.recv(1024)
    response = json.loads(response.decode())
    if response["command"] != "login":
        pass
    elif response["authResult"] == "new_user":
        # new user
        message = json.dumps({
            "command": "login",
            "username": client_username,
            "password": input("This is a new user. Please confirm your password: "),
            "private_port": private_socket.getsockname()[1]
        })
        check_login()
    elif response["authResult"] == "invalid_password":
        message = json.dumps({
            "command": "login",
            "username": client_username,
            "password": input("Invalid password. Please try again. \nPassword: "),
            "private_port": private_socket.getsockname()[1]
        })
        check_login()
    elif response["authResult"] == "block_account":
        print("Invalid password. Your account has been blocked. Please try again later.")
    elif response["authResult"] == "already_blocked":
        print("Your account is blocked due to multiple login failures. Please try again later")
    elif response["authResult"] == "already_login":
        print("You have already logged in.")
    elif response["authResult"] == "success_login":
        # login successfully
        print("Welcome to the greatest messaging application ever!")
        receiver = threading.Thread(target=recvThread, name="RecvHandler")
        receiver.daemon = True
        receiver.start() 

        sender = threading.Thread(target=sendThread, name="SendHandler")
        sender.daemon = True
        sender.start()
    
        privater = threading.Thread(target=privThread, name="PrivateRecvHandler")
        privater.daemon = True
        privater.start()

        atexit.register(stop)

        while True:        
            if stop_process:
                exit(0)
            time.sleep(0.1)

def connect_private(address, port, username):
    global client_username
    new_socket = socket(AF_INET, SOCK_STREAM)
    new_socket.connect((address, port))
    private_user_sockets[username] = new_socket

def private_msg_receive(connection_socket):
    while True:
        recv_msg = connection_socket.recv(1024)
        if not recv_msg:
            exit(0)
        recv_msg = recv_msg.decode()
        recv_msg = json.loads(recv_msg)
        if recv_msg["command"] == "close":
            sender = recv_msg["sender"]
            private_user_sockets[sender].close()
            private_user_sockets.pop(sender)
            print('stopprivate with <' + sender + '>')
        elif recv_msg["command"] == "close_logout":
            sender = recv_msg["sender"]
            private_user_sockets[sender].close()
            private_user_sockets.pop(sender)
            print(sender + ' logged out, private chat concluding')
        else:
            sender = recv_msg["sender"] 
            message = recv_msg["message"]
            print(sender+ '(private): '+ message)    

# receive private msg
def privThread():
    global private_socket
    while True:
        # new client for start private
        connection_socket, clientAddress = private_socket.accept()
        private_socket_thread = threading.Thread(target=private_msg_receive, args= (connection_socket,), name=clientAddress)
        private_socket_thread.daemon = False
        private_socket_thread.start()

# receive the response from server
def recvThread():
    global stop_process, Socket
    while True:
        response = Socket.recv(1024)
        recv_msg = json.loads(response.decode())
        if recv_msg["command"] == "message":    
            if recv_msg["respones"] == "not_exist_user":
                print("Error. Invalid user")
            elif recv_msg["respones"] == "is_self":
                print("Error. Cannot message to yourself.")
            elif recv_msg["respones"] == "block_you":
                print("Your message could not be delivered as the recipient has blocked you")
            elif recv_msg["respones"] == "ok":
                # message sent successfully
                pass
        elif recv_msg["command"] == 'broadcast':
            if recv_msg["block_sender"] == True:
                print('Your message could not be delivered to some recipients')
        elif recv_msg["command"] in ["receive_msg", "receive_bcst"]:
            # receiving a message
            print(recv_msg["sender"]+ ':'+ recv_msg["message"])
        elif recv_msg["command"] == 'whoelse':
            print("\n".join(recv_msg["response"]))
        elif recv_msg["command"] == 'whoelsesince':
            print("\n".join(recv_msg["response"]))
        elif recv_msg["command"] == 'block':
            if recv_msg["respones"] == "is_self":
                print("Error. Cannot block self")
            elif recv_msg["respones"] == "not_exist_user":
                print("Error. Invalid user.")
            else:
                print(recv_msg["user"] + " is blocked")
        elif recv_msg["command"] == 'unblock':
            if recv_msg["respones"] == "is_self":
                print("Error. Cannot unblock yourself.")
            elif recv_msg["respones"] == "not_exist_user":
                print("Error. Invalid user.")
            elif recv_msg["respones"] == "user_not_block":
                print("Error. " + recv_msg['user'] + " was not blocked.")
            else:
                print(recv_msg['user'] + " is unblocked")
        elif recv_msg["command"] == "login_broadcast":
            print(recv_msg["sender"] + ' is logged in.')
        elif recv_msg["command"] == "logout_broadcast":
            print(recv_msg["sender"] + ' is logged out.')
        elif recv_msg["command"] == "timeout":
            for username in private_user_sockets.keys():
                private_user_sockets[username].send(json.dumps({
                    "command": "close_logout",
                    "sender": client_username
                }).encode())
            stop_process = True
            print("\rYou are timed out.") 
        elif recv_msg["command"] == "refuse_private_message":
            print(recv_msg["message"]) 
        elif recv_msg["command"] == "startprivate":
            if recv_msg["response"] == "not_exist_user":
                print("Error. Invalid user.")
            elif recv_msg["response"] == "is_self":
                print("Error. Cannot private yourself.")
            elif recv_msg["response"] == "block_you":
                print("Error. User blocked you.")
            elif recv_msg["response"] == "not_online":
                print("Error. User is not online.")
            elif recv_msg["response"] == "ask_request":
                pass
        elif recv_msg["command"] == "accept_private_message":
            print(recv_msg["message"])
            address = recv_msg["socket_name"]
            port = int(recv_msg["private_port"])
            username = recv_msg["username"]
            connect_private(address, port, username)
        elif recv_msg["command"] == "ask_connect_private":
            sender = recv_msg["sender"]
            print(sender + " would like to private message, enter y or n: ")
            time.sleep(0.01)
            answer = input("")
            if answer == "n":
                # refuse connect private
                Socket.send(json.dumps({
                    "command": "refuse_private",
                    "message": recv_msg["receiver"] + " refuse private messaging",
                    "user": sender
                }).encode())
            elif answer == "y":
                # accept connect private
                address = recv_msg["sender_socket"]
                port = int(recv_msg["sender_port"])
                connect_private(address, port, sender)
                Socket.send(json.dumps({
                    "command": "accept_private",
                    "message": recv_msg["receiver"] + " accepts private messaging",
                    "sender": sender,
                    "receiver": recv_msg["receiver"]
                }).encode())
        time.sleep(0.1)

# send the command to server
def sendThread():
    global stop_process, client_username
    global Socket
    while True:
        inp = input("")
        if ' ' not in inp:
            command = inp
        else:
            command, line = inp.split(' ', 1)
        if command == "logout":
            for username in private_user_sockets.keys():
                private_user_sockets[username].send(json.dumps({
                    "command": "close_logout",
                    "sender": client_username
                }).encode())
            stop_process = True
            print("\rSuccess logout.")
        elif command == "broadcast":
            Socket.send(json.dumps({
                "command": command,
                "message": line,
            }).encode())
        elif command == "message":
            user, message = line.split(' ', 1)
            Socket.send(json.dumps({
                "command": command,
                "message": message,
                "user": user
            }).encode()) 
        elif command == "block" or command == "unblock":
            Socket.send(json.dumps({
                "command": command,
                "user": line,
            }).encode())
        elif command == "startprivate":
            Socket.send(json.dumps({
                "command": command,
                "user": line,
            }).encode())
            print("Start private messaging with " + line)
        elif command == "whoelse":
            Socket.send(json.dumps({
                "command": command
            }).encode())
        elif command == "whoelsesince":
            Socket.send(json.dumps({
                "command": command,
                "since": line
            }).encode())
        elif command == "private":
            user, message = line.split(' ', 1)
            if user in private_user_sockets and private_user_sockets[user]:
                private_user_sockets[user].send(json.dumps({
                    "command": "message",
                    "sender": client_username,
                    "message": message
                }).encode())
            else:
                print("Error. Private messaging to "+ user + " not enabled")
        elif command == "stopprivate":
            if line in private_user_sockets.keys():
                private_user_sockets[line].send(json.dumps({
                    "command": "close",
                    "sender": client_username
                }).encode())
                private_user_sockets[line].close()
                private_user_sockets.pop(line)
                print('stopprivate with <' + line + '>')
            else:
                print('startprivate was not executed with this <'+ line + '>')
        else:
            print("Error. Invalid command")
        

       
if __name__ == "__main__":
    Socket = socket(AF_INET, SOCK_STREAM)
    Socket.connect((server_name, server_port))
    # private socket
    private_socket = socket(AF_INET, SOCK_STREAM)
    private_socket.bind(('localhost', 0))
    private_socket.listen(1)
    client_username = input("Username: ")
    message = json.dumps({
        "command": "login",
        "username": client_username,
        "password": input("Password: "),
        "private_port": private_socket.getsockname()[1]
    })
    check_login()
