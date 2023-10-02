# Python3
# Zhaoyan Liu
# coding: utf-8

from Individual import Individual_Status
from typing import List, Dict
from socket import *
import time 
import json
import signal
import sys
import threading


if len(sys.argv) != 4:
    print("Usage: python3 server.py server_port block_duration timeout")
    exit(0)
serverPort = int(sys.argv[1])
block_duration = int(sys.argv[2])
time_out = int(sys.argv[3])

pending_messages = list()

condition = threading.Condition()

address_to_username = dict()

users_dict: Dict[str, Individual_Status] = dict()

# helper function
def update_user_dict():
    with open("credentials.txt", "r") as f:
        for user in f:
            username, password = user.strip().split()
            users_dict[username] = Individual_Status(block_duration, time_out, username, password)

# helper function
def authenticate(username, password):
    if username not in users_dict:
        # create a new user
        with open("credentials.txt", "a") as f:
            f.write(username+ " "+ password+"\n")
        update_user_dict()
        return "new_user"

    # then login 
    return users_dict[username].login(password)

# stop the process
def exist_process(signal, frame):
    global Socket
    print("\rServer is shutdown")
    Socket.close()
    exit(0)

# receive
def recvThread():
    global Socket
    print('Server is up.')
    while True:
        clientSockt, clientAddress = Socket.accept()
        clientThread = threading.Thread(target=send_to_client, args = (clientSockt, clientAddress), name=clientAddress)
        clientThread.daemon = False
        clientThread.start()
        time.sleep(0.02)

# send pending and time out
def sendThread():
    while True:
        with condition:
            # check timeout users
            users = set()
            for user in users_dict.values():
                if user.is_timeout():
                    users.add(user.username)
            for timeout_username in users:
                users_dict[timeout_username].online_status = False
                users_dict[timeout_username].private_port = 0
                users_dict[timeout_username].socket.send(json.dumps({"command": 'timeout'}).encode())

            # check pending messages
            for mss in pending_messages:
                receiver = mss['receiver']
                sender = mss["sender"]
                send_mss = mss["message"]
                if users_dict[receiver].online_status:
                    users_dict[receiver].socket.send(json.dumps({
                        "command": "receive_msg",
                        "sender": sender,
                        "message": send_mss
                    }).encode())
                    pending_messages.remove(mss)
            
            condition.notify()
        time.sleep(0.02)

# check command and send information to client
def send_to_client(clientSockt, clientAddress):
    while True:
        server_recv = clientSockt.recv(1024)
        if not server_recv:
            # nothing recieve
            exit(0)
        server_recv = server_recv.decode()
        server_recv = json.loads(server_recv)

        with condition:
            server_send = dict()
            server_send["command"] = server_recv["command"]
            sender = '';
            # find sender name
            if clientAddress in address_to_username:
                sender = address_to_username[clientAddress]
                # refresh the time out 
                users_dict[sender].last_inactive = (int(time.time()))
            
            if server_recv["command"] == "logout":
                users_dict[sender].online_status = False
                users_dict[sender].private_port = 0
                users_dict[sender].last_login_time = int(time.time())
                # broadcast client logout
                for user in users_dict.values():
                    if user.online_status and user.username not in users_dict[sender].blocked_users:
                        user.socket.send(json.dumps({
                            "command": 'logout_broadcast',
                            "sender": sender
                        }).encode())
            elif server_recv["command"] == "login":
                username = server_recv["username"]
                password = server_recv["password"]
                address_to_username[clientAddress] = username
                # authenticate this client
                result = authenticate(username, password)
                server_send["authResult"] = result
                if result == "success_login":
                    # add the socket and private port to individual
                    users_dict[username].socket = clientSockt
                    users_dict[username].private_port = int(server_recv["private_port"])
                    # broadcast new client login
                    for user in users_dict.values():
                        if user.username != username and user.online_status and user.username not in users_dict[username].blocked_users:
                            user.socket.send(json.dumps({
                                "command": "login_broadcast",
                                "sender": username
                            }).encode())
            elif server_recv["command"] == "broadcast":
                # broadcast the message to online unblocked users
                message = server_recv["message"]
                blocked_sender = False
                for user in users_dict.values():
                    if sender in user.blocked_users:
                        blocked_sender = True
                    elif user.online_status and user.username != sender:
                        user.socket.send(json.dumps({
                            "command": "receive_bcst",
                            "sender": sender,
                            "message": message
                        }).encode())
                server_send["block_sender"] = blocked_sender
            elif server_recv["command"] == "message":
                receiver = server_recv["user"]
                message = server_recv["message"]
                if receiver not in users_dict:
                    server_send["respones"] = "not_exist_user"
                elif sender == receiver:
                    server_send["respones"] = "is_self"
                elif sender in users_dict[receiver].blocked_users:
                    server_send["respones"] = "block_you"
                else:
                    server_send["respones"] = "ok"
                    if not users_dict[receiver].online_status:
                        pending_messages.append({
                            "sender": sender,
                            "receiver": receiver,
                            "message": message
                        })
                    else:
                        users_dict[receiver].socket.send(json.dumps({
                            "command": "receive_msg",
                            "sender": sender,
                            "message": message
                        }).encode())             
            elif server_recv["command"] == "unblock":
                unblock_user = server_recv["user"]
                if unblock_user not in users_dict:
                    server_send["respones"] = "not_exist_user"
                elif sender == unblock_user:
                    server_send["respones"] = "is_self"
                elif unblock_user not in users_dict[sender].blocked_users:
                    server_send["respones"] = "user_not_block"
                    server_send["user"] = unblock_user
                else:
                    server_send["respones"] = "ok"
                    server_send["user"] = unblock_user
                    users_dict[sender].blocked_users.remove(unblock_user)
            elif server_recv["command"] == "block":
                block_user = server_recv["user"]
                if block_user not in users_dict:
                    server_send["respones"] = "not_exist_user"
                elif sender == block_user:
                    server_send["respones"] = "is_self"
                else:
                    server_send["respones"] = "ok"
                    server_send['user'] = block_user
                    users_dict[sender].blocked_users.add(block_user)
            elif server_recv["command"] == "whoelsesince":
                users = set()
                for user in users_dict:
                    t = int(time.time()) - int(server_recv['since'])
                    if ((users_dict[user].last_login_time > t) or (users_dict[user].online_status)) and (sender not in users_dict[user].blocked_users): 
                        users.add(user)
                if sender in users:
                    # remove sender
                    users.remove(sender)                      
                server_send["response"] = list(users)
            elif server_recv["command"] == "whoelse":
                online_users = set()
                for user in users_dict:
                    if users_dict[user].online_status and sender not in users_dict[user].blocked_users:
                        online_users.add(user)
                # remove sender self
                if sender in online_users:
                    online_users.remove(sender)
                server_send["response"] = list(online_users)
            elif server_recv["command"] == "refuse_private":
                user = server_recv["user"]
                users_dict[user].socket.send(json.dumps({
                    "command": "refuse_private_message",
                    "message": server_recv["message"]
                }).encode())
            elif server_recv["command"] == "startprivate":
                # return user address and port if available
                receiver = server_recv["user"]
                if receiver not in users_dict:
                    server_send["response"] = "not_exist_user"
                elif receiver == sender:
                    server_send["response"] = "is_self"
                elif not users_dict[receiver].online_status:
                    server_send["response"] = "not_online"
                elif sender in users_dict[receiver].blocked_users:
                    server_send["response"] = "block_you" 
                else:
                    # ask for user
                    server_send["response"] = "ask_request" 
                    users_dict[receiver].socket.send(json.dumps({
                        "command": "ask_connect_private",
                        "sender": sender,
                        "sender_socket": users_dict[sender].socket.getsockname()[0],
                        "sender_port": users_dict[sender].private_port,
                        "receiver": receiver
                    }).encode()) 
            elif server_recv["command"] == "accept_private":
                receiver = server_recv["receiver"]
                user = users_dict[receiver]
                s = server_recv["sender"]
                users_dict[s].socket.send(json.dumps({
                    "command": "accept_private_message",
                    "message": server_recv["message"],
                    "username": user.username,
                    "socket_name": user.socket.getsockname()[0],
                    "private_port": user.private_port 
                }).encode())
            # send message to the client
            clientSockt.send(json.dumps(server_send).encode())  
            condition.notify()

if __name__ == '__main__':
    update_user_dict() 
    Socket = socket(AF_INET, SOCK_STREAM)
    Socket.bind(('localhost', serverPort))
    Socket.listen()
    
    # reference from https://blog.csdn.net/dongfuguo/article/details/53899426
    receiver = threading.Thread(target=recvThread, name="Server_recvThread")
    receiver.daemon = True
    receiver.start()

    sender = threading.Thread(target=sendThread, name="Server_sendThread")
    sender.daemon = True
    sender.start()

    # control + c
    signal.signal(signal.SIGINT, exist_process)

    while (1):
        time.sleep(0.02)
        # count time account block
        for user_credential in users_dict.values():
            user_credential.update_account_block()
