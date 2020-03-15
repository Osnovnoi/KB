from tkinter import *
import sqlite3
import re
import Main_mode
import threading
import getpass,socket,hashlib,winreg
from tkinter import messagebox
from git.repo.base import Repo

import os, random, struct
from Crypto.Cipher import AES

def Hash_calculation():
		digest = hashlib.md5()
		hash_str = ""
		hash_str += getpass.getuser()
		hash_str += socket.gethostname()
		hash_str += os.environ['WINDIR'] 
		digest.update(hash_str.encode('utf-8'))
		return digest.hexdigest()

def Registry_insert(user):
			digest = Hash_calculation()
			try:
				key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Король", 0, winreg.KEY_ALL_ACCESS)
				get = winreg.QueryValueEx(key,"Signature")[0]
			except Exception:
				user.user.root.withdraw()
				messagebox.showerror("Error", "NO ENTRY FOR Signature checking") 
				user.root.destroy()
			if str(get) != str(Hash_calculation()):
				user.root.withdraw()
				messagebox.showerror("Error", "WRONG HASH!") 
				user.root.destroy()
			key.Close()
			decrypt_file(get.encode(),"/sqlite/data.enc")




def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        decryptor = AES.new(key, AES.MODE_ECB)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

	
class GUI:
	def __init__(self):
		self.root = Tk()
		self.root.title("AUTHENTICATION")
		self.root.geometry("300x300")
		self.login = StringVar()
		self.password = StringVar()

		self.Error_label = Label(self.root,width = 30,fg = "red",text = "")
		self.login_field = Entry(self.root,width = 30,textvariable = self.login )
		self.password_field = Entry(self.root,width = 30,show="*",textvariable = self.password)
		self.Submit = Button(self.root,text = "LOGIN",padx =50,pady = 50,command= self.click)

		self.Error_label.place(x = 30 ,y = 15)
		self.login_field.place(x = 50 ,y = 50)
		self.password_field.place(x = 50 ,y = 80)
		self.Submit.place(x = 70 ,y = 120)

		self.Error_queqe = []
		self.Error_count = 0

	

	def validate(self,l,p):
		####
		#
		#change pattern_p just for avoiding sql-INjections,and then CREATE func to check the password-type Restritions
		
			pattern_p = re.compile(r'[0-9]{0,20}$')
			pattern_l = re.compile(r'[a-zA-Z0-9]{5,20}$')
			if not pattern_l.match(l):
				self.Error_queqe.insert(-1,"InValid syntax for LOGIN!")
				raise Exception ("InValid syntax for LOGIN!")


			if not pattern_p.match(p):
				self.Error_queqe.insert(-1,"InValid syntax for password!")
				raise Exception ("InValid syntax for password!")


	def Authenticicate(self,login,passwd):
		con = sqlite3.connect('sqlite/data')

		digest = hashlib.sha1()
		digest.update(passwd.encode())
		pass_hash = str(digest.hexdigest())

		cursor = con.cursor()
		cursor.execute("""SELECT LOGIN,PASSWD,Limitation,Status FROM USERS WHERE LOGIN = ? AND PASSWD = ?""",(login,pass,))
		user_data = cursor.fetchone()
		if not user_data or user_data == None:
			self.Error_queqe.insert(-1,"Inccorect password or Login!")
			raise Exception("Inccorect password or Login!")

		cursor.close()
		con.close()
		self.Error_label.config(text = "")
		return user_data



	def click(self):
		get_pass = self.password.get()
		get_log = self.login.get()
		try:
			self.validate(get_log,get_pass)
			user_data = self.Authenticicate(get_log,get_pass)
		except Exception as msg:

			self.Error_count += 1
			if self.Error_count > 2:
				self.root.destroy()
				return

			self.Error_label.config(text = self.Error_queqe.pop())

			print(self.Error_count,"Error_count")
		else:
			task1 = threading.Thread(target =self.root.destroy())
			Main_mode.Main_mode(user_data)




A = GUI()
Registry_insert(A)

A.root.mainloop()


		

		


