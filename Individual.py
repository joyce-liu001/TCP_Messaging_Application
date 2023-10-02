from time import time
from typing import Set

class Individual_Status:
    # store user's status and information
    def __init__(self, count_blocktime, count_timeout, username, password):
        self.password = password
        self.username = username
        self.private_port = 0
        self.online_status = False
        self.last_login_time = 0
        
        self.last_inactive = int(time())
        self.count_timeout = count_timeout
        
        self.count_fail_login = 0
        self.account_blockedsince = 0
        self.count_blocktime = count_blocktime
        self.account_blocked = False
        self.socket = None
        self.blocked_users = set() 

    def login(self, password_input):
        if self.account_blocked:
            return "already_blocked"
        elif self.online_status:
            return "already_login"
        elif self.password != password_input:
            self.count_fail_login += 1
            if self.count_fail_login >= 3:
                self.account_blockedsince = int(time())
                self.account_blocked = True
                return "block_account"  
            return "invalid_password"
        else:
            # success log in
            self.online_status = True
            self.last_login_time = int(time())
            self.count_fail_login = 0
            self.account_blockedsince = 0
            self.last_inactive = int(time())
            return "success_login"

    def update_account_block(self):
        # update user account block status
        if self.account_blockedsince + self.count_blocktime < int(time()) and self.account_blocked:
            self.account_blocked = False

    def is_timeout(self):
        # update user time out status
        if self.last_inactive + self.count_timeout < int(time()) and self.online_status:
            self.online_status = False
            self.private_port = 0
            self.last_inactive = 0
            return True
        return False