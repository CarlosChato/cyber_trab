import tkinter as tk
import json 
from tkinter import messagebox
from MainPage import MainPage

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.fernet import Fernet

class MyApp(tk.Tk):
    def __init__(self, *args, **kwargs):

        tk.Tk.__init__(self, *args, **kwargs)

        container = tk.Frame(self, highlightcolor="red")
        container.pack( side = "top", fill = "both", expand = True )

        

        container.grid_rowconfigure(0,weight = 1)
        container.columnconfigure(0,weight = 1)

        self.frames = {}

        for F in (Home, LogIn, MainPage,SignUp):#we have to set all the screens into ()
            
            frame = F(container,self)

            self.frames[F] = frame

            frame.grid(row=0,column=0, sticky="nsew")

        self.show_frame(Home)
    
    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()

class Home(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        login_butt = tk.Button(self, text="Login", width=20, height=2,
                                command=lambda:controller.show_frame(LogIn))

        sign_up_butt = tk.Button(self, text = "Sign Up", width=20, height=2,
                                 command=lambda:controller.show_frame(SignUp))

        login_butt.pack(pady=(200,10),padx=200) #padding 200px for top and 10 px for bot
        sign_up_butt.pack(pady=(10,200),padx=200) #padding like the last one, but inverse


class SignUp(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        user = tk.Label(self, text="user", width=20, height=2)
        entry_name = tk.Entry(self,  width=40)

        email = tk.Label(self, text="email", width=20, height=2)
        entry_email = tk.Entry(self,  width=40)

        password = tk.Label(self,text="password", width=20)
        entry_pass = tk.Entry(self,width=40,show="*")

        password2 = tk.Label(self,text="repeat password", width=20)
        entry_pass2 = tk.Entry(self,width=40,show="*")

        sing_up = tk.Button(self, text="Sing Up",width=20, height=2,
                            command=lambda:self.checks(entry_name.get(), 
                            entry_email.get(),entry_pass.get(),
                            entry_pass2.get(), controller))
        
        #//////////////// UI section/////////////////////

        user.grid(row=0,column=1,pady=(50,5),padx=(20,1)) 
        entry_name.grid(row=0,column=4,pady=(50,5)) 

        email.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_email.grid(row=2,column=4,pady=(50,5))

        password.grid(row=4,column=1,pady=(50,5),padx=(20,1))
        entry_pass.grid(row=4,column=4,pady=(50,5))

        password2.grid(row=6,column=1,pady=(50,5),padx=(20,1))
        entry_pass2.grid(row=6,column=4,pady=(50,5))

        sing_up.grid(row=8,column=4,pady=(50,5),padx=(20,1))

    def checks(self, user, email, pass1, pass2, controller):
        #Check all the data of the sign up

        if pass1 != pass2:
            messagebox.showerror("Error","Passwords have to be the same")

        if len(pass1) <=5:
            messagebox.showerror("Error","Passwords have to have five caracters minimun")
        
        if len(email)<= 0:
            messagebox.showerror("Error","It isn't an email")

        if len(user) <= 0:
            messagebox.showerror("Error","You have to set an username")
        
        signed = self.check_already_signed(user,email)

        if signed==True:
            self.add_user(user, email, pass1, controller)

        elif signed=="user":
            messagebox.showerror("Error","User is already registered")
        elif signed=="email":
            messagebox.showerror("Error","Email is already registered")

    def add_user(self, user, email, pwd, controller):
        data2={"name": user, "pwd": pwd, "email": email}
        with open("store_login/data.json", "r") as outfile:
            data = json.load(outfile)

        data.append(data2)
        

        with open("store_login/data.json", "w") as file:
            json.dump(data, file)
        
        


        controller.show_frame(MainPage)            
                

            
    def check_already_signed(self, name, email):
        try:
            with open("store_login/data.json", "r") as f:
                try:
                    data = json.load(f)

                except:
                    return True
        except:
            messagebox.showerror("Error","Error: the file doesn't exist")

        for user in data:
            if name == user["name"]: 
                return "user"
            if email == user["email"]:
                return "email"
        return True


class LogIn(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        user = tk.Label(self, text="user", width=20, height=2)
        entry_name = tk.Entry(self,  width=40)
        password = tk.Label(self,text="password", width=20)
        entry_pass = tk.Entry(self,width=40,show="*")
        login_butt = tk.Button(self, text="Login", width=5, height=2,
                               command=lambda:self.check_user(entry_name.get(), entry_pass.get(), controller))

        user.grid(row=0,column=1,pady=(50,5),padx=(20,1)) 
        entry_name.grid(row=0,column=4,pady=(50,5)) 
        password.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_pass.grid(row=2,column=4,pady=(50,5))
        login_butt.grid(row= 4,column=4,pady=(50,5),padx=(20,1))


    def check_user(self,name,pwd,controller):

        with open("store_login/data.json", "r") as f:
            try:
                data = json.load(f)

            except:
                print("hoao")
                messagebox.showerror("Error","Wrong username or password")


        found = False
        for user in data:
            if name == user["name"] and pwd == user["pwd"]:
                found = True
                break
        
        if found:    
            controller.show_frame(MainPage)

        else:
            messagebox.showerror("Error","Wrong username or password")

class MainPage(tk.Frame):
    ## Recordar de poner un campo en el json de texto

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        note_butt = tk.Button(self, text="Note", width=20, height=3,
                                command=lambda:controller.show_frame(WriteNote))


        note_butt.pack(pady=(200,10),padx=200) #padding 200px for top and 10 px for bot

class WriteNote(tk.Frame):

    def __init__(self, parent, controller):
        user = tk.Label(self, text="note", width=20, height=2)
        entry_note = tk.Entry(self,  width=40, height = 40)
    
        note_butt = tk.Button(self, text="Add Note", width=20, height=3,
                                command=lambda:controller.write_note(entry_note.get))

    


        


        
        




        

app = MyApp()
app.mainloop()  