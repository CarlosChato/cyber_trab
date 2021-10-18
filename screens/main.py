import base64
import json
import os
import tkinter as tk
from tkinter import Label, messagebox,Entry, ttk
from tkinter.constants import SINGLE

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# This is the initial class, which make the principal window and inicialitation of all windows
class MyApp(tk.Tk):
    """ constructor method """ 
    def __init__(self, *args, **kwargs):

        # we have to call to the parent's init
        tk.Tk.__init__(self, *args, **kwargs)

        # define of the container
        container = tk.Frame(self, highlightcolor="red")
        container.pack( side = "top", fill = "both", expand = True )

        

        container.grid_rowconfigure(0,weight = 1)
        container.columnconfigure(0,weight = 1)

        # Create a dictionary about frames (the differents windows will be classes)
        self.frames = {}

        # Loop to initialize all the classes and save it into a dictionary
        for F in (Home, LogIn, MainPage, SignUp, WriteNote, DeleteNote):#we have to set all the screens into ()
            
            frame = F(container,self)

            self.frames[F] = frame

            frame.grid(row=0,column=0, sticky="nsew")

        # The first frame to show is Home
        self.show_frame(Home)

        # Function to change the title of the app
        self.make_widgets()

    def make_widgets(self):
        
        self.winfo_toplevel().title("My Diario")
    
    # Function to change the differents frames when it'll necessary
    def show_frame(self, cont, user = None):

        frame = self.frames[cont]
        # If we want to save the user of the other window, the user will be different at None
        if user != None:
            frame.user = user
            
        frame.tkraise()

class Home(tk.Frame):
    """ Class that will show the initial frame with the login and sign up buttons"""

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)

        # The declaration of the two buttons of the initial frame.
        login_butt = tk.Button(self, text="Login", width=20, height=2,
                                command=lambda:controller.show_frame(LogIn))

        sign_up_butt = tk.Button(self, text = "Sign Up", width=20, height=2,
                                 command=lambda:controller.show_frame(SignUp))

        # It will place the buttons correctly
        login_butt.pack(pady=(200,10),padx=200) #padding 200px for top and 10 px for bot
        sign_up_butt.pack(pady=(10,200),padx=200) #padding like the last one, but inverse


class SignUp(tk.Frame):
    """ This is the frame for the Sign Up duty """

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)

        # Declaration of the entries for the user, mail and password (twice)
        user = tk.Label(self, text="user", width=20, height=2)
        entry_name = tk.Entry(self,  width=40)

        email = tk.Label(self, text="email", width=20, height=2)
        entry_email = tk.Entry(self,  width=40)

        password = tk.Label(self,text="password", width=20)
        entry_pass = tk.Entry(self,width=40,show="*")

        password2 = tk.Label(self,text="repeat password", width=20)
        entry_pass2 = tk.Entry(self,width=40,show="*")

        # Button to confirm the data introduced. When clicked: function call to function checks
        sing_up = tk.Button(self, text="Sing Up",width=20, height=2,
                            command=lambda:self.checks(entry_name.get(), 
                            entry_email.get(),entry_pass.get(),
                            entry_pass2.get(), controller))

        
        # This is the return button
        back_butt = tk.Button(self, text="Go back", width=20, height=2, command=lambda:controller.show_frame(Home))
        
        #//////////////// UI section, placing the elements/////////////////////

        user.grid(row=0,column=1,pady=(50,5),padx=(20,1)) 
        entry_name.grid(row=0,column=4,pady=(50,5)) 

        email.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_email.grid(row=2,column=4,pady=(50,5))

        password.grid(row=4,column=1,pady=(50,5),padx=(20,1))
        entry_pass.grid(row=4,column=4,pady=(50,5))

        password2.grid(row=6,column=1,pady=(50,5),padx=(20,1))
        entry_pass2.grid(row=6,column=4,pady=(50,5))

        sing_up.grid(row=8,column=4,pady=(50,5),padx=(20,1))
        
        back_butt.grid(row=10, column= 4, pady=(50,5),padx=(20,1))

    def checks(self, user, email, pass1, pass2, controller):
        #Checks all the data of the sign up

        if pass1 != pass2:
            messagebox.showerror("Error","Passwords have to be the same")

        if len(pass1) <=5:
            messagebox.showerror("Error","Passwords have to have five caracters minimun")
        
        if len(email)<= 0:
            messagebox.showerror("Error","It isn't an email")

        if len(user) <= 0:
            messagebox.showerror("Error","You have to set an username")
        
        # Function call to check_already_singed to see if the user was already in
        signed = self.check_already_signed(user,email)

        if signed==True:
             # If True, the user wasn't found so it adds the user (function call to add_user)
            self.add_user(user, email, pass1, controller)

        elif signed=="user":
            messagebox.showerror("Error","User is already registered")
        elif signed=="email":
            messagebox.showerror("Error","Email is already registered")

    def add_user(self, user, email, pwd, controller):
        # This function will add the user to the data.json with the password passed through the MAC algorithm
        self.user = user
        
        user = user

        # It generates a random salt to encrypt the password
        salt_pass = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_pass,
            iterations=100000,
        )

        # The password is derivated by encoding it to latin-1 and then derive it with the kdf algorithm already defined
        key = kdf.derive(pwd.encode('latin-1'))

        # After this it decodes the encrypted password @param key and this will be what will be saved in the data.json
        key2 = key.decode('latin-1')

        # Also, it decodes the salt already generated to save it in the data.json
        salt_pass2 = salt_pass.decode("latin-1")
        
        # It stores the new user data in the data.json
        data2={"name": user, "pwd": key2, "email": email, "salt_p":salt_pass2}
        with open("store_login/data.json", "r") as outfile:
            data = json.load(outfile)

        data.append(data2)
        

        with open("store_login/data.json", "w") as file:
            json.dump(data, file)
        
        


        controller.show_frame(MainPage, user)
                

            
    def check_already_signed(self, name, email):
        # This funtion will check if the user is already registered

        # It will try to open the file, if it doesn't exist => error
        try:
            with open("store_login/data.json", "r") as f:

                # It will try to load the data from the data.json, if it can't be opened is that there is no users in the data.json
                try:
                    data = json.load(f)

                except:
                    return True
        except:
            messagebox.showerror("Error","Error: the file doesn't exist")

        # It will check if the user is in data.json or the email is in data.json
        for user in data:
            if name == user["name"]: 
                return "user"
            if email == user["email"]:
                return "email"
        return True


class LogIn(tk.Frame):
    """ This is the frame for the Log In duty """

    def __init__(self, parent, controller):
        
        # This will initialize the frame

        tk.Frame.__init__(self, parent)

        # Declaration of the entries for the user and password
        user = tk.Label(self, text="user", width=20, height=2)
        entry_name = tk.Entry(self,  width=40)
        password = tk.Label(self,text="password", width=20)
        entry_pass = tk.Entry(self,width=40,show="*")

        # If the login_button Button is clicked it will do a function call to check_user to check if the user is already registered
        login_butt = tk.Button(self, text="Login", width=5, height=2,
                               command=lambda:self.check_user(entry_name.get(), entry_pass.get(), controller))
                               
        # This is the return button
        back_butt = tk.Button(self, text="Go back", width=20, height=2, command=lambda:controller.show_frame(Home))

        #//////////////// UI section, placing the elements/////////////////////
        user.grid(row=0,column=1,pady=(50,5),padx=(20,1)) 
        entry_name.grid(row=0,column=4,pady=(50,5)) 
        password.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_pass.grid(row=2,column=4,pady=(50,5))
        login_butt.grid(row= 4,column=4,pady=(50,5),padx=(20,1))

        back_butt.grid(row=10, column= 4, pady=(50,5),padx=(20,1))


    def check_user(self,name,pwd,controller):
        # This function will check if the user is already registered

        # It will try to open the data.json
        with open("store_login/data.json", "r") as f:
            try:
                data = json.load(f)

            except:
                messagebox.showerror("Error","Wrong username or password")


        # Defining a variable found will allow the program to find out if the user is already registered
        found = False

        # It will compare all of the users in data with the user introduced in the entry
        for user in data:

            # If the user is in already, it will decrypt the password using the MAC algorithm to autenticate the user.
            if name == user["name"]:

                # As the data.json already has the encrypted pwd and the salt used to encrypt it, it will be used to decrypt the pwd and compare it to the password introduced in the entry
                pass_e = user["pwd"]
                salt_e = user["salt_p"]

                # It defines the MAC algorithm with the salt in the data.json
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt_e.encode("latin-1"),
                    iterations=100000,
                )
                
                # It verifies if the password decrypted and the given one in the entry are the same
                try:
                    kdf.verify(pwd.encode("latin-1"),pass_e.encode("latin-1"))
                except:
                    break
                found = True
                break
        
        # If the encryption is a success, the comparition of the encrypted pwd and the password given is correct and the user has been found,
        # the MainPage frame will be shown
        if found:    
            controller.show_frame(MainPage,name)

        else:
            messagebox.showerror("Error","Wrong username or password")


class WriteNote(tk.Frame):
    """ This is the frame for the Write Note duty """

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)


        # User is none, to have the global user after this (we)
        self.user = None

        # Declaration of the entries for the note and date of the new note
        note = tk.Label(self, text="note", width=20, height=2)
        entry_note = tk.Entry(self,  width=40)
        date = tk.Label(self, text="date", width=20, height=2)
        entry_date = tk.Entry(self,  width=40)
    
        note_butt = tk.Button(self, text="Add Note", width=20, height=3,
                                command=lambda:self.write_note(entry_note.get(), entry_date.get()))
        back_butt = tk.Button(self, text="Go back", width=20, height=2, command=lambda:controller.show_frame(MainPage))

        note.grid(row=0,column=1,pady=(50,5),padx=(20,1))
        entry_note.grid(row=0,column=4,pady=(50,5))
        date.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_date.grid(row=2,column=4,pady=(50,5))

        note_butt.grid(row= 4,column=4,pady=(50,5),padx=(20,1)) 

        back_butt.grid(row=10, column= 4, pady=(50,5),padx=(20,1))


    def write_note(self, note, date):
        
        is_note = False
        data2 = None
        
        with open("store_login/notes.json", "r") as outfile:
            data = json.load(outfile)
        
        for i in data:
            if i["user"] == self.user and i["date"] == date:
                is_note = True
                data2 = i
                data.remove(i)
                break
        
        # exists the note of that day
        if is_note:
            data2["notes"] = note
            data.append(data2)
        
        # case the note of that day doesn't exist
        else:
            data2 = {"user": self.user, "date" : date, "notes": note}
            data.append(data2)
        

        with open("store_login/notes.json", "w") as file:
            json.dump(data, file)

class DeleteNote(tk.Frame):

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)


        # User is none, to have the global user after this (It initializes the self.user)
        # self.user = None
        
        # rows = []

        # for i in range(5):

        #     cols = []

        #     for j in range(4):

        #         e = Entry(relief="groove")

        #         e.grid(row=i, column=j, sticky="nsew")

        #         e.insert("end", '%d.%d' % (i, j))

        #         cols.append(e)

        #     rows.append(cols)
        #note_butt = tk.Button(self, text="Add Note", width=20, height=3,
                                #command=lambda:self.show_notes()) 
        
        #note_butt.grid(row= 0,column=4,pady=(50,5),padx=(20,1))

                
    def show_notes(self):

        with open("store_login/notes.json", "r") as outfile:
            data = json.load(outfile)

        for i in data:
            if i["user"] == self.user:
                
                tree.insert(" ", "end", text=str(cont), values=(str(cont), i["notes"]))

        tree.pack()
        

class MainPage(tk.Frame):
    """ This is the frame for the Main Page duty """

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent)
        #self.user = SignUp.user
        
        self.user = None

        note_butt = tk.Button(self, text="Add note/edit note", width=20, height=3,
                                command=lambda:controller.show_frame(WriteNote,self.user))

        note_butt1 = tk.Button(self, text="Delete note", width=20, height=3,
                                command=lambda:controller.show_frame(DeleteNote,self.user))
        
        note_butt2 = tk.Button(self, text="Mostrar user", width=20, height=3,
                                command=lambda:self.mostrar_user())
                                
        back_butt = tk.Button(self, text="Cerrar sesión", width=20, height=2, command=lambda:controller.show_frame(Home))
        
        
        

        note_butt.grid(row=0, column=4,pady=(50,5),padx=(20,1)) #padding 200px for top and 10 px for bot
        note_butt1.grid(row=2, column=4,pady=(50,5),padx=(20,1))
        note_butt2.grid(row=4, column=4,pady=(50,5),padx=(20,1))
        back_butt.grid(row=6, column= 4, pady=(50,5),padx=(20,1))

        
        


    def mostrar_user(self):
        print("mostrar user: ", self.user)

        
        
        

app = MyApp()
app.mainloop()  
