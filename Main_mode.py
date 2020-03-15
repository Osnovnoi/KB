from tkinter  import *
from tkinter  import messagebox
import re
import sqlite3
import threading,hashlib

### Write a func to avoid sql-injections on new_password
def Sql_injection_avoidance(passwd):
	fobitten_symbols = ["!","@","\'","-","\"","+","*","?",">","<",".","=","#","(",")","~"]
	for i in passwd:
		if i in fobitten_symbols:
			return False
	return True

def pass_validation(obj,old_pass,new_pass = None):
	# Nolimitations,Defalt "NONE" just for using same func in entry load proccess
	if obj.limit == 0 and new_pass == None:
		return True

		#No limitation,but new_pass is not NOne,so it used it pass_changing procedure
	if obj.limit == 0 and new_pass != None:
		if obj.passwd == old_pass and Sql_injection_avoidance(new_pass):
			return True
		return False

		#limitation,None- will be required to rechange pass
	if obj.limit == 1 and new_pass == None:
		pattern_p = re.compile(r'[0-9]{6,20}$')
		if not pattern_p.match(old_pass):
			return False
		return True

		#limitation,notNone- new password does not match to restriction pattern
	if obj.limit == 1 and new_pass != None:
		pattern_p = re.compile(r'[0-9]{6,20}$')
		if not pattern_p.match(new_pass) :
			return False
		return True
		

class User(Frame):

	def __init__(self,parent,data):
		super().__init__()

		self.container = parent # to manipulate root inside class
		self.container.resizable(False, False) # not resizable in both directions
		self.container.geometry("320x315")

		self.login = data[0]
		self.passwd  = data[1]
		self.limit  = data[2]
		self.status =data[3]
		if self.status:
			self.Block_warning()
		else:
			self.Error_count = 0
	#if users pass do not follow pass restrictions - go to pass change
			Force = threading.Thread(target =self.Force_pass_change())
			Force.start()
			Force.join()
			
			self.container.title(f"WELCOME :{self.login}")

			Submit = Button(self,width =30,text = "Password_change",padx =50,pady = 40,bg= 'red',command = self.Pass_change_WIN)
			Submit.grid(row = 0 , column = 0)
			self.pack(fill=BOTH, expand=1)

	def Block_warning(self):
		self.container.withdraw()
		messagebox.showerror("Error", "YOU ARE BLOCKED")
		self.container.destroy()
		

#put into function to overload for admin(to ignore - pass_restrictions )
	def Force_pass_change(self):
		if not pass_validation(self,self.passwd):
			self.Pass_change_WIN()


	def Pass_change_WIN(self):
		pass_window = Toplevel()
		pass_window.resizable(False,False)
		pass_window.title("CHANGE PASSWORD")

		if type(self) == User and self.limit == 1:## for forsing user to change password
			self.container.withdraw()
			pass_window.protocol("WM_DELETE_WINDOW", lambda: self.container.destroy())
		old = StringVar()
		new = StringVar()

		old_pass = Entry(pass_window,width = 30,textvariable = old,show ="*" )
		new_pass  = Entry(pass_window,width = 30,textvariable = new,show ="*")

		Btn = Button(pass_window, width = 30,text = "CHANGE",command = lambda:self.Password_Submit(old.get(),new.get(),Error_label,pass_window) )
		Error_label = Label(pass_window,width = 30,fg = "red",text = "")


		old_pass.grid(row = 1,column = 0)
		new_pass.grid(row = 2,column = 0)
		Btn.grid(row = 3,column = 0 )
		Error_label.grid(row = 0,column = 0)



	def Password_Submit(self,old_pass,new_pass,Error_lbl,pass_window):
		try:
			if not pass_validation(self,old_pass,new_pass):
				raise Exception ("Incorrect old Password or Invalid New")
			con = sqlite3.connect('sqlite/data')
			cursor = con.cursor()
			digest = hashlib.sha1()
			digest.update(new_pass.encode())
			new_pass = str(digest.hexdigest())
			
			cursor.execute("""UPDATE USERS SET Passwd = ? Where LOGIN = ?""",(new_pass,self.login,))######
	
			con.commit()
			cursor.close()
			con.close()

			pass_window.destroy()
			self.container.deiconify()

		except Exception as msg:

			self.Error_count += 1
			Error_lbl.config(text = msg)
#destroy if users with limits waisted to many tries
			if self.Error_count > 2  and self.limit == 1 and type(self) == User:
				self.container.destroy()





class Admin(User):
	def __init__(self,parent,data):
		super().__init__(parent,data)#initiate Users abilities
		Apply_user = Button(self,width = 20,text = "Create User",bg= 'red',padx = 5,command= lambda:self.User_creation(Create.get()))
		Apply_user.place(x = 160,y = 150)

		self.Error_l = 	Label(self,width = 30,fg = "red",text = "")
		self.Error_l.grid(row= 1,column = 0)

		Create = StringVar()
		#will validate new user login
		reg = self.register(self.validate_login)
		Create_user = Entry(self,width = 16,validate = "key",validatecommand  =(reg,'%P'),font = "Times 15",border = 2,textvariable = Create)
		Create_user.place(x = 0,y = 150)

		self.user_data = self.get_users_data()
		self.us_login = list(self.user_data.keys())

		self.choice = StringVar()

		self.Limit_ind  = BooleanVar()
		self.Block_ind  = BooleanVar()
		self.choice.trace('w',self.changed)
		#for initial reaction on choice
		self.choice.set(self.login)


		Limit = Checkbutton(text="LIMIT", variable=self.Limit_ind)
		Block =  Checkbutton(text="BLOCK", variable=self.Block_ind)

		Limit.place(x =50,y = 210)
		Block.place(x = 200 ,y = 210)

		Users_stat = OptionMenu(self,self.choice,*self.us_login)
		Users_stat.config(width= 45 ,fg = "red",padx = 10)
		Users_stat.place(x = 0,y = 175)
		#Apply new perms if Checkbuttom changed
		Submit_permitions = Button(self,width = 30 ,text = "Apply",bg= "red",padx = 51,pady = 15,command = self.Apply_user_changes)
		Submit_permitions.place(x = 0,y = 260)

#####does not work without *args???
	def changed(self,*args):
		print(self.user_data[self.choice.get()])
		v1,v2 = self.user_data[self.choice.get()]
		self.Limit_ind.set(v1)
		self.Block_ind.set(v2)

	def get_users_data(self):
		con = sqlite3.connect('sqlite/data')
		cursor = con.cursor()
		cursor.execute("""SELECT LOGIN,Limitation,Status FROM USERS""")
		data = cursor.fetchall()
		print(data)
		user_data   = {}
		for line in data:
			user_data[line[0]] = (line[1],line[2])
		print(user_data)
		con.commit()
		cursor.close()
		con.close()
		return user_data

	def Apply_user_changes(self):
		if self.user_data[self.choice.get()] == (self.Limit_ind.get(),self.Block_ind.get()):
			self.Error_l.config(text = "This changes have been already applied!")
		else:
			try:
				con = sqlite3.connect('sqlite/data')
				cursor = con.cursor()
				cursor.execute(
				"""UPDATE  USERS SET Limitation = ?,Status = ? WHERE LOGIN = ?""",
				( self.Limit_ind.get(),self.Block_ind.get(),self.choice.get(),))######

				con.commit()
				cursor.close()
				con.close()
			except Exception:
				self.Error_l.config(text = "Unable to apply changes!")
			else:
				self.user_data[self.choice.get()] = self.Limit_ind.get(),self.Block_ind.get()
				print(self.user_data[self.choice.get()])



	def validate_login(self,login):
		pattern_l = re.compile(r'[a-zA-Z0-9]{0,20}$')
		if not pattern_l.match(login):
			return False
		return True

	def User_creation(self,login):
		try:
			if len(login) < 5:
				raise Exception ("Login < 5 symbols")
		#CREATE CHECK FOR UNIQUE LOGIN(REturnig erros fron DB is incorrect)
		#
		except Exception  as msg:
			self.Error_l.config(text= msg)
		else:
			try:
				con = sqlite3.connect('sqlite/data')
				cursor = con.cursor()
				cursor.execute("""INSERT INTO USERS VALUES(NULL,?,'',0,0,0)""",(login,))######
				con.commit()
				cursor.close()
				con.close()
			except Exception:
				self.Error_l.config(text ="DB is DisAble!")
			##REminder to update dropdown when creating new user
			
			#self.user_data[login] = (0,0)
			#self.us_login.append(login)


	def Force_pass_change(self):
		if not pass_validation(self,self.passwd):
			pass###ignore inccrorect password

	def Block_warning(self):
		messagebox.showerror("Error","YOUR 'BLOCK' flag is up!")



def Main_mode(data):
	root = Tk()
	if  not data[0]:
		root.destroy()
	if data[0] == "ADMIN":
		A = Admin(root,data)
		root.mainloop()
	else:
		A = User(root,data)
		root.mainloop()

