import socket, threading
import tkinter as tk
import tkinter.scrolledtext
import easygui
import smtplib
from tkinter import *
from tkinter import messagebox
from aes import Crypt_aes
from session_keys import DH
from random import randint

class Client:
    def __init__(self):
        self.port=6543
        self.server=socket.gethostbyname(socket.gethostname())
        self.client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.header=1024
        self.format="utf-8"
        self.client_name=None
        self.disconnect='nfgbuitgrudvjuirdt'
        self.client_key=DH()
        self.client_pub_key=str(self.client_key.pub_key_generate())
        self.client_pvt_key=None
        self.gui_done=False
        
    def start_client(self):
        self.client.connect((self.server,self.port))
        self.name= None
        self.keys_exchange()
        gui_thread=threading.Thread(target=self.main_gui)
        gui_thread.start()
        
    def main_gui(self):
        self.main_window = Tk()
        self.main_window.title('Главное меню')
        self.main_window.geometry('350x150')
        self.main_window.resizable(False, False)

        self.regist_btn = Button(self.main_window, text='Регистрация', command=self.reg)
        self.regist_btn.pack(padx=10, pady=12)

        self.autoris_btn = Button(self.main_window, text='Авторизация', command=self.auth)
        self.autoris_btn.pack(padx=10, pady=12)

        self.autoris_btn = Button(self.main_window, text='Восстановить пароль', command=self.rest_password)
        self.autoris_btn.pack(padx=10, pady=12)

        self.main_window.protocol("WM_DELETE_WINDOW", self.stop)
        self.main_window.mainloop()

    def reg(self):
        self.main_window.quit()
        self.main_window.destroy()
        msg = self.aes.encrypt('regist')
        self.client.send(msg)
        self.regist_gui()

    def auth(self):
        self.main_window.quit()
        self.main_window.destroy()
        msg=self.aes.encrypt('autoris')
        self.client.send(msg)
        self.authen_gui()

    def rest_password(self):
        self.main_window.quit()
        self.main_window.destroy()
        msg=self.aes.encrypt('rest_password')
        self.client.send(msg)
        self.rest_pass_gui()

    def gui(self):
        self.win=Tk()
        self.win.geometry("700x450")
        self.win.maxsize(700,400)
        self.win.minsize(700,400)
        self.win.configure(bg='#e8e8e5')

        self.chat_area=tkinter.scrolledtext.ScrolledText(self.win, height=12, bg="#FFFFFF")
        self.chat_area.pack(padx=0, pady=5)
        self.chat_area.insert('end', 'Вы присоеденились к чату.\n')
        self.chat_area.config(state="disabled", font=("Arial",12))

        self.msg_label=tk.Label(self.win, text="Напишите ваше сообщение", anchor="w", justify="left", bg="#e8e8e5")
        self.msg_label.config(font=("Arial",12))
        self.msg_label.pack(padx=25,pady=5, anchor=NW)

        self.input_area=tk.Text(self.win, height=3, bg="#FFFFFF")
        self.input_area.pack(padx=0,pady=5)

        self.send_button=tk.Button(self.win, text="Отправить", bg="#FFFFFF", command=self.send_message)
        self.send_button.config(font=("Arial", 12))
        self.send_button.place(x=578, y=345)
        
        self.gui_done=True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)
        self.win.mainloop()

    def send_message(self):
        msg=f"{self.input_area.get('1.0', 'end').strip()}\n"
        if len(msg)==1:
            return
        msg=self.aes.encrypt(msg)
        self.client.send(msg)
        self.input_area.delete('1.0', 'end')

    def stop(self):
        self.client.send(self.aes.encrypt(self.disconnect))
        self.client.close()
        exit(0)

    def keys_exchange(self):
        server_pub_key=int(self.client.recv(self.header).decode(self.format))
        self.client_pvt_key=self.client_key.gen_shared_key(server_pub_key)
        self.client.send(self.client_pub_key.encode(self.format))
        self.aes=Crypt_aes(self.client_pvt_key)

    def regist_gui(self):
        self.window = Tk()
        self.window.title('Регистрация')
        self.window.geometry('380x350')
        self.window.resizable(False, False)

        self.font_header = ('Arial', 15)
        self.font_entry = ('Arial', 12)
        self.label_font = ('Arial', 11)
        self.base_padding = {'padx': 10, 'pady': 8}
        self.header_padding = {'padx': 10, 'pady': 12}

        self.main_label = Label(self.window, text='Регистрация', font=self.font_header, justify=CENTER, **self.header_padding)
        self.main_label.grid(row=0, column=0, columnspan=2)

        self.firstname_label = Label(self.window, text='Имя', font=self.label_font , **self.base_padding)
        self.firstname_label.grid(row=1, column=0, padx=10, sticky=tk.W)

        self.firstname_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry)
        self.firstname_entry.grid(row=1, column=1, padx=[0, 10], pady=5)

        self.surename_label = Label(self.window, text='Фамилия', font=self.label_font , **self.base_padding)
        self.surename_label.grid(row=2, column=0, padx=10, sticky=tk.W)

        self.surename_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry)
        self.surename_entry.grid(row=2, column=1, padx=[0, 10], pady=5)

        self.mailname_label = Label(self.window, text='Электронная почта', font=self.label_font , **self.base_padding)
        self.mailname_label.grid(row=3, column=0, padx=10, sticky=tk.W)

        self.mailname_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry)
        self.mailname_entry.grid(row=3, column=1, padx=[0, 10], pady=5)

        self.username_label = Label(self.window, text='Имя пользователя', font=self.label_font , **self.base_padding)
        self.username_label.grid(row=4, column=0, padx=10, sticky=tk.W)

        self.username_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry)
        self.username_entry.grid(row=4, column=1, padx=[0, 10], pady=5)

        self.password_label = Label(self.window, text='Пароль', font=self.label_font , **self.base_padding)
        self.password_label.grid(row=5, column=0, padx=10, sticky=tk.W)

        self.password_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry, show='*')
        self.password_entry.grid(row=5, column=1, padx=[0, 10], pady=5)

        self.password_label_2 = Label(self.window, text='Повторите пароль', font=self.label_font , **self.base_padding)
        self.password_label_2.grid(row=6, column=0, padx=10, sticky=tk.W)

        self.password_entry_2 = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry, show='*')
        self.password_entry_2.grid(row=6, column=1, padx=[0, 10], pady=5)
        
        self.send_btn = Button(self.window, text='Зарегистрироваться', command=self.regist)
        self.send_btn.place(x=235, y=300)

        self.window.protocol("WM_DELETE_WINDOW", self.stop)
        self.window.mainloop()

    def mail_send(self, email, msg):
        sender = 'valiantsoldier@mail.ru'
        password = 'JGbSkNsbztKY3aBnnsVS'

        msg = str(msg)
        serverSMTP = smtplib.SMTP_SSL('smtp.mail.ru', 465)
        serverSMTP.login(sender, password)
        serverSMTP.sendmail(sender, email, f"Subject: The code to confirm registration.\n{msg}")

    def regist(self):
        firstname=f"{self.firstname_entry.get()}"
        surname=f"{self.surename_entry.get()}"
        email=f"{self.mailname_entry.get()}"
        msg_1=f"{self.username_entry.get()}"
        msg_2=f"{self.password_entry.get()}"
        msg_3=f"{self.password_entry_2.get()}"
        msg=f"{firstname} {surname} {email}"
        firstsuremail = firstname + surname + email

        while True:

            if len(firstname) <= 1 or len(surname) <= 1 or len(email) <= 1:
                messagebox.showinfo('Заголовок', 'Некоторые данные не были заполнены'.format())
                break

            for el in firstsuremail:
                if el == ' ':
                    messagebox.showinfo('Заголовок', 'В имени, фамилии или электронной почте не должно присутствовать пробелов'.format())
                    break

            if len(msg_1) < 4 or len(msg_2) < 4:
                messagebox.showinfo('Заголовок', 'Логин или пароль должны иметь не менее 4 символов'.format())
                break
            
            if len(msg_1) > 30 or len(msg_2) > 20:
                messagebox.showinfo('Заголовок', 'Логин должен иметь не более 30 символов, а пароль не более 20'.format())
                break

            cyrillic_and_space_str = list('абвгдеёжзийклмнопрстуфхцчшщъыьэюя ')
            password_list = list(msg_2.lower())
            for el in password_list:
                if el in cyrillic_and_space_str:
                    messagebox.showinfo('Заголовок', 'В логине и пароле не должны использоваться пробелы и символы из кириллицы'.format())
                    return False

            valid_characters_str = list('abcdefghijklmnopqrstuvwxyz_123456789')
            login_list = list(msg_1.lower())
            for el in login_list:
                if el not in valid_characters_str:
                    messagebox.showinfo('Заголовок', 'В логине допустимы только латинские символы, цифры и нижнее подчеркивание'.format())
                    return False

            if msg_2 != msg_3:
                messagebox.showinfo('Заголовок', 'Пароли не совпадают, попробуйте ещё раз'.format())
                break
            
            msg_1=self.aes.encrypt(msg_1)
            msg_2=self.aes.encrypt(msg_2)

            self.client.send(msg_1)
            if self.client.recv(self.header).decode(self.format) == '200':
                self.client.send(msg_2)
            else:
                messagebox.showinfo('Заголовок', 'Такой логин уже существует'.format())
                break
            if self.client.recv(self.header).decode(self.format) == '200':
                pincod = randint(100000, 999999)
                self.mail_send(email, pincod)
                pincod_client = str(easygui.enterbox("Введите отправленный на почту код", "Код подтверждения почты"))
                if pincod_client != str(pincod):
                    messagebox.showinfo('Заголовок', 'Неверный код'.format())
                    self.client.send('400'.encode(self.format))
                    break
            self.client.send(msg.encode(self.format))
            messagebox.showinfo('Заголовок', 'Регистрация прошла успешно'.format())
            self.window.quit()
            self.window.destroy()
            self.authen_gui()
            break

    def rest_pass_gui(self):
        self.window = Tk()
        self.window.title('Восстановление пароля')
        self.window.geometry('450x120')
        self.window.resizable(False, False)

        self.usernamerest_label = Label(self.window, text='Введите ваш логин', font=('Arial', 11) , padx=10, pady=8)
        self.usernamerest_label.pack()

        self.usernamerest_entry = Entry(self.window, bg='#fff', fg='#444', font=('Arial', 12))
        self.usernamerest_entry.pack()

        self.autoris_btn = Button(self.window, text='OK', command=self.rest_pass)
        self.autoris_btn.pack(padx=10, pady=12)

        self.window.protocol("WM_DELETE_WINDOW", self.stop)
        self.window.mainloop()

    def new_pass_gui(self):
        self.window = Tk()
        self.window.title('Новый пароль')
        self.window.geometry('450x230')
        self.window.resizable(False, False)

        self.new_pass_label = Label(self.window, text='Введите дважды ваш новый пароль', font=('Arial', 11) , padx=10, pady=8)
        self.new_pass_label.pack(padx=10, pady=12)

        self.new_pass_entry = Entry(self.window, bg='#fff', fg='#444', font=('Arial', 12))
        self.new_pass_entry.pack(padx=10, pady=12)

        self.new_pass_entry_2 = Entry(self.window, bg='#fff', fg='#444', font=('Arial', 12))
        self.new_pass_entry_2.pack(padx=10, pady=12)

        self.autoris_btn = Button(self.window, text='OK', command=self.new_pass)
        self.autoris_btn.pack(padx=10, pady=12)

        self.window.protocol("WM_DELETE_WINDOW", self.stop)
        self.window.mainloop()

    def rest_pass(self):
        msg=f"{self.usernamerest_entry.get()}"
        msg=self.aes.encrypt(msg)

        while True:
            self.client.send(msg)
            email = self.client.recv(self.header).decode(self.format)
            if email == '400':
                messagebox.showinfo('Заголовок', 'Логин введен неправильно или не существует'.format())
                break
            else:
                pincod = randint(100000, 999999)
                self.mail_send(email, pincod)
                pincod_client = str(easygui.enterbox("Введите отправленный на почту код", "Восстановление пароля"))
                if pincod_client != str(pincod):
                    messagebox.showinfo('Заголовок', 'Неверный код'.format())
                    self.client.send('400'.encode(self.format))
                    break
                self.client.send('200'.encode(self.format))
                self.window.quit()
                self.window.destroy()
                self.new_pass_gui()
                break

    def new_pass(self):
        password_1=f"{self.new_pass_entry.get()}"
        password_2=f"{self.new_pass_entry_2.get()}"

        while True:
            if 4 > len(password_1) > 20:
                messagebox.showinfo('Заголовок', 'Пароль должен иметь от 4 до 20 символов'.format())
                break

            cyrillic_and_space_str = list('абвгдеёжзийклмнопрстуфхцчшщъыьэюя ')
            password_list = list(password_1.lower())
            for el in password_list:
                if el in cyrillic_and_space_str:
                    messagebox.showinfo('Заголовок', 'В пароле не должны использоваться пробелы и символы из кириллицы'.format())
                    return False

            if password_1 != password_2:
                messagebox.showinfo('Заголовок', 'Пароли не совпадают, попробуйте ещё раз'.format())
                break
            
            password_1=self.aes.encrypt(password_1)
            self.client.send(password_1)
            self.window.quit()
            self.window.destroy()
            self.authen_gui()
            break

    def authen_gui(self):
        self.window = Tk()
        self.window.title('Авторизация')
        self.window.geometry('450x300')
        self.window.resizable(False, False)

        self.font_header = ('Arial', 15)
        self.font_entry = ('Arial', 12)
        self.label_font = ('Arial', 11)
        self.base_padding = {'padx': 10, 'pady': 8}
        self.header_padding = {'padx': 10, 'pady': 12}

        self.main_label = Label(self.window, text='Авторизация', font=self.font_header, justify=CENTER, **self.header_padding)
        self.main_label.pack()

        self.username_label = Label(self.window, text='Имя пользователя', font=self.label_font , **self.base_padding)
        self.username_label.pack()

        self.username_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry)
        self.username_entry.pack()

        self.password_label = Label(self.window, text='Пароль', font=self.label_font , **self.base_padding)
        self.password_label.pack()

        self.password_entry = Entry(self.window, bg='#fff', fg='#444', font=self.font_entry, show='*')
        self.password_entry.pack()
        
        self.send_btn = Button(self.window, text='Войти', command=self.authen)
        self.send_btn.place(x= 200, y=180)

        self.window.protocol("WM_DELETE_WINDOW", self.stop)
        self.window.mainloop()

    def authen(self):

        msg_1=f"{self.username_entry.get()}"
        msg_2=f"{self.password_entry.get()}"

        msg_1=self.aes.encrypt(msg_1)
        msg_2=self.aes.encrypt(msg_2)

        while True:
            self.client.send(msg_1)
            if self.client.recv(self.header).decode(self.format) == '200':
                self.client.send(msg_2)
            status = self.client.recv(self.header).decode(self.format)
            if status == '200':
                pincod = randint(100000, 999999)
                email = self.client.recv(self.header).decode(self.format)
                self.mail_send(email, pincod)
                pincod_client = str(easygui.enterbox("Введите отправленный на почту код", "Подтверждение входа"))
                if pincod_client != str(pincod):
                    messagebox.showinfo('Заголовок', 'Неверный код'.format())
                    self.client.send('400'.encode(self.format))
                    break
                self.client.send('200'.encode(self.format))
                self.name_send()
                self.window.quit()
                self.window.destroy()
                gui_thread=threading.Thread(target=self.gui)
                gui_thread.start()
                receive_thread=threading.Thread(target=self.receive)
                receive_thread.start()
                break
            elif status == '400':
                messagebox.showinfo('Заголовок', 'Неверный логин или пароль, попробуйте ещё раз'.format())
                break

    def name_send(self):
        if self.name is None:
            self.name= self.username_entry.get()
        self.client.send(self.name.encode(self.format))

    def receive(self):
        while True:
            try:
                message=self.client.recv(self.header)
                if self.gui_done:
                    message=self.aes.decrypt(message)
                    self.chat_area.config(state='normal')
                    self.chat_area.insert('end', message)
                    self.chat_area.yview('end')
                    self.chat_area.config(state='disabled')
            except:
                print("Disconnected from server")
                messagebox.showinfo('Заголовок', 'Вы были отключены от сервера из-за проблем с сетью, либо на ваш аккаунт зашли с другого устройства'.format())
                self.win.quit()
                self.win.destroy()
                break

new_cl=Client()
new_cl.start_client()