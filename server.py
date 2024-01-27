import socket, threading
from aes import Crypt_aes
from session_keys import DH
import psycopg2
import hashlib
import smtplib
from os import urandom
from binascii import hexlify
import time

class Server:

    def __init__(self):
        self.port=6543
        self.host=socket.gethostbyname(socket.gethostname())
        self.server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.header=1024
        self.format="utf-8"
        self.conn = psycopg2.connect(database='postgres', user='postgres', host='localhost', port='5432', password='qwe123')
        self.cur = self.conn.cursor()
        self.server_key=DH()
        self.server_pub_key=str(self.server_key.pub_key_generate())
        self.authen_correct = 0
        self.client_first_sur_names={}
        self.client_names={}
        self.client_keys={}
        self.disconnect='nfgbuitgrudvjuirdt'

    def broadcast(self,msg):
        for client in self.client_names:
            aes=Crypt_aes(self.client_keys[client])
            crypted_msg=aes.encrypt(msg)
            client.send(crypted_msg)
    
    def name_recv(self, client):
        msg=client.recv(self.header).decode(self.format)
        self.cur.execute(f"select firstname, surname from user_data where username like '{msg}'")
        result = self.cur.fetchall()
        self.client_first_sur_names[client] = result[0][0] + ' ' + result[0][1]
        if msg in list(self.client_names.values()):
            keys = [key for key in self.client_names if self.client_names[key] == msg]
            for el in keys:
                el.close()
        self.client_names[client]=msg

    def mail_send(self, email, msg):
        sender = 'valiantsoldier@mail.ru'
        password = 'JGbSkNsbztKY3aBnnsVS'

        serverSMTP = smtplib.SMTP_SSL('smtp.mail.ru', 465)
        serverSMTP.login(sender, password)
        serverSMTP.sendmail(sender, email, str(msg))

    def registration(self, client):
        client_pvt_key=self.client_keys[client]
        aes=Crypt_aes(client_pvt_key)
        while True:
            msg_1 = aes.decrypt(client.recv(self.header))
            if msg_1 == self.disconnect:
                break
            self.cur.execute('select username from user_data')
            results = self.cur.fetchall()
            result = [x[0] for x in results]
            if msg_1 in result:
                client.send(('400').encode(self.format))
                continue
            client.send(('200').encode(self.format))
            msg_2 = aes.decrypt(client.recv(self.header))
            if msg_2 == self.disconnect:
                break
            client.send(('200').encode(self.format))
            msg = client.recv(self.header).decode(self.format)
            if msg == self.disconnect:
                break
            elif msg == '400':
                continue
            else:
                list_msg = msg.split()

            salt = hexlify(urandom(32)).decode('ascii')
            password_salt = msg_2 + salt
            password_salt_hash = hashlib.sha256(password_salt.encode(self.format)).hexdigest()
            self.cur.execute(f"insert into user_data (username, password, salt, firstname, surname, email) values ('{msg_1}', '{password_salt_hash}', '{salt}', '{list_msg[0]}', '{list_msg[1]}', '{list_msg[2]}')")
            self.conn.commit()
            self.authentication(client)
            break

    def rest_pass(self, client):
        client_pvt_key=self.client_keys[client]
        aes=Crypt_aes(client_pvt_key)
        while True:
            login = aes.decrypt(client.recv(self.header))
            if login == self.disconnect:
                break
            self.cur.execute(f"select email, salt from user_data where username like '{login}'")
            results = self.cur.fetchall()
            if len(results) == 0:
                client.send(('400').encode(self.format))
                continue
            else:
                email = results[0][0]
                salt = results[0][1]
                client.send((f'{email}').encode(self.format))
            msg = client.recv(self.header).decode(self.format)
            if msg == self.disconnect:
                break
            elif msg == '200':
                new_password = aes.decrypt(client.recv(self.header))
                if new_password == self.disconnect:
                    break
                else:
                    password_salt = new_password + salt
                    password_salt_hash = hashlib.sha256(password_salt.encode(self.format)).hexdigest()
                    self.cur.execute(f"update user_data SET password='{password_salt_hash}' WHERE username='{login}'")
                    self.conn.commit()
                    self.authentication(client)
                    break

    def authentication(self, client):
        client_pvt_key=self.client_keys[client]
        aes=Crypt_aes(client_pvt_key)
        while True:
            msg_1 = aes.decrypt(client.recv(self.header))
            if msg_1 == self.disconnect:
                break
            client.send(('200').encode(self.format))
            msg_2 = aes.decrypt(client.recv(self.header))
            if msg_2 == self.disconnect:
                break
            self.cur.execute('select username from user_data')
            results = self.cur.fetchall()
            result = [x[0] for x in results]

            if msg_1 in result:
                self.cur.execute(f"select password, salt, email from user_data where username like '{msg_1}'")
                results_2 = self.cur.fetchall()
                email = results_2[0][2]
                password_salt = msg_2 + results_2[0][1]
                password_salt_hash = hashlib.sha256(password_salt.encode('utf_8')).hexdigest()
                if password_salt_hash == results_2[0][0]:
                    client.send(('200').encode(self.format))
                    client.send((f'{email}').encode(self.format))
                else:
                    client.send(('400').encode(self.format))
                    continue
                msg = client.recv(self.header).decode(self.format)
                if msg == self.disconnect:
                    break
                elif msg == '200':
                    self.authen_correct = 1
                    break
            else:
                client.send(('400').encode(self.format))

    def key_exchange(self, client):
        client.send((self.server_pub_key).encode(self.format))
        client_pub_key=int(client.recv(self.header).decode(self.format))
        client_pvt_key=self.server_key.gen_shared_key(client_pub_key)
        self.client_keys[client]=client_pvt_key

    def handle_client(self,client,client_addr):
        client_pvt_key=self.client_keys[client]
        client_name=self.client_names[client]
        client_first_sur_name=self.client_first_sur_names[client]
        self.cur.execute(f"select msg, aes_key from user_msg order by id desc limit 50")
        last_msgs_data = self.cur.fetchall()
        last_msgs = []
        for i in last_msgs_data:
            aes=Crypt_aes(i[1])
            msg = aes.decrypt(i[0])
            last_msgs.append(msg)

        print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - Connected")
        print(f"Active Connections - {threading.active_count()-1}")

        aes=Crypt_aes(client_pvt_key)

        time.sleep(0.5)
        for i in last_msgs[::-1]:
            msg_crypt = aes.encrypt(i)
            time.sleep(0.01)
            client.send(msg_crypt)

        self.broadcast(f'{client_first_sur_name} присоединился к чату!\n')

        while True:
            try:
                msg = aes.decrypt(client.recv(self.header))
                if msg==self.disconnect:
                    break
                print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_first_sur_name}] - {msg}")
                msg=f'{client_first_sur_name}: {msg}'
                self.broadcast(msg)
                msg = aes.encrypt(msg)
                msg = str(msg.decode(self.format))
                self.cur.execute(f"insert into user_msg (msg, aes_key) values ('{msg}', '{client_pvt_key}')")
                self.conn.commit()
            except:
                break

        client.close()
        print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - Disconnected")
        del self.client_names[client]
        del self.client_keys[client]
        del self.client_first_sur_names[client]
        self.broadcast(f'{client_first_sur_name} покинул чат!\n')
        print(f"Active Connections - {threading.active_count()-2}")

    def work_server(self, client, client_addr):
            self.key_exchange(client)
            client_pvt_key=self.client_keys[client]
            aes=Crypt_aes(client_pvt_key)
            msg = aes.decrypt(client.recv(self.header))
            if msg == 'regist':
                self.registration(client)
            elif msg == 'rest_password':
                self.rest_pass(client)
            elif msg == self.disconnect:
                return False
            else:
                self.authentication(client)
            if self.authen_correct == 1:
                self.name_recv(client)
                thread = threading.Thread(target=self.handle_client, args=(client, client_addr))
                thread.start()
                self.authen_correct = 0

    def start_server(self):
        self.server.bind((self.host,self.port))
        self.server.listen()
        print(f"Server is starting...\nServer [{self.host}] is ready to accept connections!")
        while True:
            client, client_addr = self.server.accept()
            thread_work_server = threading.Thread(target=self.work_server, args=(client, client_addr))
            thread_work_server.start()
       
serv=Server()
serv.start_server()