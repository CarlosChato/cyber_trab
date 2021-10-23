import base64
import json
import os
import random
import tkinter as tk
from tkinter import Entry, Label, messagebox, ttk
from tkinter.constants import SINGLE

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#******************************************************************************************
# This is the initial class, which make the principal window and inicialitation of all windows
#******************************************************************************************
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
        for F in (Home, LogIn, MainPage, SignUp, WriteNote, ShowNote, DeleteNote):#we have to set all the screens into ()

            # Saving the class into the dictionaty            
            frame = F(container,self)

            self.frames[F] = frame

            frame.grid(row=0,column=0, sticky="nsew")

        # The first frame to show is Home
        self.show_frame(Home)

        # Function to change the title of the app
        self.make_widgets()

    # Function to set the title into the window, on upper place
    def make_widgets(self):
        
        self.winfo_toplevel().title("My Diario")
    
    # Function to change the differents frames when it'll necessary
    def show_frame(self, cont, user = None):

        frame = self.frames[cont]

        # If we want to save the user of the other window, the user will be different at None
        if user != None:
            frame.user = user
            
        frame.tkraise()


#******************************************************************************************
# Class Home
#******************************************************************************************
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
        login_butt.grid(pady=(200,10),padx=200) #padding 200px for top and 10 px for bot
        sign_up_butt.grid(pady=(10,200),padx=200) #padding like the last one, but inverse


#******************************************************************************************
# Class SignUp
#******************************************************************************************
class SignUp(tk.Frame):
    """ This is the frame for the Sign Up duty """

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)

        # Declaration of the entries for the user, mail and password (twice)
        # And declaration of the labels to show a message to the user
        user = tk.Label(self, text="user", width=20, height=2)
        entry_name = tk.Entry(self,  width=40)

        email = tk.Label(self, text="email", width=20, height=2)
        entry_email = tk.Entry(self,  width=40)

        password = tk.Label(self,text="password", width=20)
        entry_pass = tk.Entry(self,width=40,show="*")

        password2 = tk.Label(self,text="repeat password", width=20)
        entry_pass2 = tk.Entry(self,width=40,show="*") # "*" is used to hide the input text

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

    # Function to check if all parameters introduced by the user are correct or not
    def checks(self, user, email, pass1, pass2, controller):
        # Checks all the data of the sign up

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

        # Errors about if the user is already used in the data base
        elif signed=="user":
            messagebox.showerror("Error","User is already registered")

        elif signed=="email":
            messagebox.showerror("Error","Email is already registered")

    #Function to add the user into the JSON file
    def add_user(self, user, email, pwd, controller):

        # This function will add the user to the data.json with the password passed through the HMAC algorithm
        self.user = user
        
        user = user

        # It generates a random salt to encrypt the password
        salt_pass = os.urandom(16)

        salt_sim = os.urandom(16)

        # Define the object about HMAC's class
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
        data2={"name": user, "pwd": key2, "email": email, "salt_p":salt_pass2, "salt_sim": salt_sim.decode("latin-1")}
        with open("store_login/data.json", "r") as outfile:
            data = json.load(outfile)

        data.append(data2)
        

        with open("store_login/data.json", "w") as file:
            json.dump(data, file)
    
        # Change the frame to the MainPage
        controller.show_frame(MainPage, user)
                
    # Function to check if the user is already signed
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
        # Error if the Json file doesn't exist
        except:
            messagebox.showerror("Error","Error: the file doesn't exist")

        # It will check if the user is in data.json or the email is in data.json
        for user in data:
            if name == user["name"]: 
                return "user"
            if email == user["email"]:
                return "email"
        return True


#******************************************************************************************
# Class LogIn
#******************************************************************************************
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

    # Function to check the user
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

        # In other case, it'll show an error message
        else:
            messagebox.showerror("Error","Wrong username or password")


#******************************************************************************************
# Class WriteNote
#******************************************************************************************
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
    
        # Declaration of the button to add note
        note_butt = tk.Button(self, text="Add Note", width=20, height=3,
                                command=lambda:self.write_note(entry_note.get(), entry_date.get()))

        # Declaration of the Button to return to the MainPage
        back_butt = tk.Button(self, text="Go back", width=20, height=2, command=lambda:controller.show_frame(MainPage))

        # ///////////////////UI section, placing the elements//////////////////////////
        note.grid(row=0,column=1,pady=(50,5),padx=(20,1))
        entry_note.grid(row=0,column=4,pady=(50,5))
        date.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_date.grid(row=2,column=4,pady=(50,5))

        note_butt.grid(row= 4,column=4,pady=(50,5),padx=(20,1)) 

        back_butt.grid(row=10, column= 4, pady=(50,5),padx=(20,1))
        
    # Function to write a note
    def write_note(self, note, date):
        # This function will write a note into @notes.json file

        # Declare a var to see if the note is already in the json or not
        is_note = False
        data2 = None
        
        # Open the data.json to get the salt 
        with open("store_login/data.json", "r") as outfile1:
            data3 = json.load(outfile1)

        # Search to get the pwd token and the iv if it exists
        for i in data3:
            if i["name"] == self.user:
                pwd = i["pwd"]
                salt_sim = i["salt_sim"]
                salt_sim = salt_sim.encode("latin-1")

                # the pwd must be byte, so it's encode as latin-1
                pwd = pwd.encode("latin-1")
                # Try: if iv exists it's save in "iv" var
                try:
                    iv = i["iv"].encode("latin-1")

                # If iv doesn't exist, it'll be create
                except:
                    # Call to the function to create the iv
                    iv = self.create_salt()
                    iv = iv.encode("latin-1")

        # Define the object about HMAC's class
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_sim,
            iterations=100000,
        )

        # The password is derivated by encoding it to latin-1 and then derive it with the kdf algorithm already defined
        key = kdf.derive(pwd)

        # Create the object of the mac class where it's used the key and sha 256 to generate the mac about note
        h = hmac.HMAC(key, hashes.SHA256())

        # Here we make the mac of the note
        h.update(note.encode("latin-1"))
        note_mac = h.finalize()
        
        
        # Creation a object about Cipher to encrypt the note
        # The encryption will be AES with CTR 
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()

        # Encrypt the note and it'll be return into ct var to save it after the encryption
        ct = encryptor.update(note.encode("latin-1")) + encryptor.finalize()    
        
        # Open the notes.json file
        with open("store_login/notes.json", "r") as outfile:
            data = json.load(outfile)
        
        # Loop to see if the note exists 
        for i in data:
            if i["user"] == self.user and i["date"] == date:
                is_note = True
                data2 = i
                data.remove(i)
                break
        
        # Exists the note of that day
        if is_note:
            
            data2["notes"] = ct.decode("latin-1")
            data2["mac"] = note_mac.decode("latin-1")
            data.append(data2) 
        
        # Case the note of that day doesn't exist
        else:
            data2 = {"user": self.user, "date" : date, "notes": ct.decode("latin-1"), "mac":note_mac.decode("latin-1")}
            data.append(data2)
        
        # Open the notes.json file to save the new note 
        with open("store_login/notes.json", "w") as file:
            json.dump(data, file)


    # Function to create the Initialization Vector (iv)
    def create_salt(self):

        # It generates a pseudorandom byte-string iv
        iv = os.urandom(16)

        # It opens the data.json to load the data
        with open("store_login/data.json", "r") as outfile:
            data3 = json.load(outfile)

        # Loop to search the user in the json and to add a iv asociated to the user
        for i in data3:
            if i["name"] == self.user:
                iv = iv.decode("latin-1")
                data3.remove(i)
                i["iv"] = iv
                data3.append(i)
                break

        # It dumps the new data in the data.json        
        with open("store_login/data.json", "w") as outfile1:
            json.dump(data3, outfile1)

        # Returns the iv to use it later
        return iv      
        

#******************************************************************************************
# Class ShowNote
#******************************************************************************************
class ShowNote(tk.Frame):
    """ This is the frame for the Write Note duty """

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)


        # User is none, to have the global user after this
        self.user = None

        # We create two buttons, one to show all the notes and the other one to go back
        note_butt = tk.Button(self, text="Show notes", width=20, height=3,
                                command=lambda:self.show_note(parent))

        note_butt.grid(row= 4,column=4,pady=(50,5),padx=200)
        
        # This is the return button
        back_butt = tk.Button(self, text="Go back", width=20, height=2, command=lambda:controller.show_frame(MainPage))
        back_butt.grid(row=15, column= 4, pady=(50,5),padx=200)


    # Function to show all the notes of an user
    def show_note(self, parent):

        # It opens the data.json to load the data
        with open("store_login/data.json", "r") as outfile1:
            data3 = json.load(outfile1)

        # It will search in the json for the data of the user and it will save in pwd the password (token of the password) and in iv the iv of the user
        for i in data3:
            if i["name"] == self.user:
                pwd = i["pwd"]
                salt_sim = i["salt_sim"]
                salt_sim = salt_sim.encode("latin-1")
                pwd = pwd.encode("latin-1")
                iv = i["iv"].encode("latin-1")

        # Defines the object about HMAC's class
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_sim,
            iterations=100000,
        )

        # The password is derivated by encoding it to latin-1 and then derive it with the kdf algorithm already defined
        key = kdf.derive(pwd)

        

        # It opens the notes.json to load the data        
        with open("store_login/notes.json", "r") as outfile:
            data = json.load(outfile)

        # This is the part where it shows the notes of the user after decrypting them
        notes = "\n"
        cont = 1

        # Loop to search in the notes all the notes of the user
        for i in data:
            if i["user"] == self.user:

                # After finding one note of the user it creates the cipher to decrypt the encrypted notes
                cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

                # It defines the decryptor using AES and CTR using the token of the password and the iv of the user
                decryptor = cipher.decryptor()

                # It defines the msg that will show in the label of the frame. This msg will contain the j-note decrypted.
                msg = decryptor.update(i["notes"].encode("latin-1")) + decryptor.finalize()

                # Create the object af Hmac with the key (provided of the hash pwd) and sha 256
                h = hmac.HMAC(key, hashes.SHA256())

                # Hmac of the msg to compare after that with the hmac of the json file
                h.update(msg)

                # Get the mac of the json
                note_mac = i["mac"].encode("latin-1")
                
                # Check if the msg is the same to hace integrity with the notes
                try:
                    h.verify(note_mac)

                except:
                    messagebox.showerror("error","Something was wrong with the note :(")
                

                # This will update the whole text of notes that will be shown to the user
                notes += "Nota " + str(cont) + ": Date: " + i["date"] + ", Nota: " + msg.decode("latin-1") + "\n"
                cont += 1

        # Then it creates the note and places it (with the text that it has been accumulating)
        note = Label(self, text=notes, width=100)
        note.grid(row=1,column=4,pady=(50,5),padx=(20,1))


#******************************************************************************************
# Class ShowNote
#******************************************************************************************
class DeleteNote(tk.Frame):
    """ This is the frame for the Delete Note duty """

    def __init__(self, parent, controller):

        # This will initialize the frame
        tk.Frame.__init__(self, parent)


        # User is none, to have the global user after this (we)
        self.user = None

        # Declaration of the entry date of the note to delete and the buttons to show notes and to delete a note

        text_del = Label(self,text = "Introduce the date of the note you want to delete")
        text_del.grid(row = 2, column=0, pady=(50,5), padx = 10)
        
        entry_date = tk.Entry(self,  width=40)
        entry_date.grid(row = 2, column = 4, pady=(50,5), padx=10)

        note_butt = tk.Button(self, text="Show notes", width=20, height=3,
                                command=lambda:self.show_note(parent))

        note_butt.grid(row= 4,column=4,pady=(50,5))

        del_butt = tk.Button(self, text="Delete Note", width=20, height=3,
                                command=lambda:self.delete(entry_date.get(), parent))

        del_butt.grid(row= 6,column=4,pady=(50,5))
        
        # This is the return button
        back_butt = tk.Button(self, text="Go back", width=20, height=2, command=lambda:controller.show_frame(MainPage))
        back_butt.grid(row=15, column= 4, pady=(50,5))


    # Function to show all the notes of an user
    def show_note(self, parent):

        # It opens the data.json to load the data
        with open("store_login/data.json", "r") as outfile1:
            data3 = json.load(outfile1)

        # It will search in the json for the data of the user and it will save in pwd the password (token of the password) and in iv the iv of the user
        for i in data3:
            if i["name"] == self.user:
                pwd = i["pwd"]
                salt_sim = i["salt_sim"]
                salt_sim = salt_sim.encode("latin-1")
                pwd = pwd.encode("latin-1")
                iv = i["iv"].encode("latin-1")

        # Defines the object about HMAC's class
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_sim,
            iterations=100000,
        )

        # The password is derivated by encoding it to latin-1 and then derive it with the kdf algorithm already defined
        key = kdf.derive(pwd)

        

        # It opens the notes.json to load the data        
        with open("store_login/notes.json", "r") as outfile:
            data = json.load(outfile)

        # This is the part where it shows the notes of the user after decrypting them
        notes = "\n"
        cont = 1

        # Loop to search in the notes all the notes of the user
        for i in data:
            if i["user"] == self.user:

                # After finding one note of the user it creates the cipher to decrypt the encrypted notes
                cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

                # It defines the decryptor using AES and CTR using the token of the password and the iv of the user
                decryptor = cipher.decryptor()

                # It defines the msg that will show in the label of the frame. This msg will contain the j-note decrypted.
                msg = decryptor.update(i["notes"].encode("latin-1")) + decryptor.finalize()

                # Create the object af Hmac with the key (provided of the hash pwd) and sha 256
                h = hmac.HMAC(key, hashes.SHA256())

                # Hmac of the msg to compare after that with the hmac of the json file
                h.update(msg)

                # Get the mac of the json
                note_mac = i["mac"].encode("latin-1")
                
                # Check if the msg is the same to hace integrity with the notes
                try:
                    h.verify(note_mac)

                except:
                    messagebox.showerror("error","Something was wrong with the note :(")
                

                # This will update the whole text of notes that will be shown to the user
                notes += "Nota " + str(cont) + ": Date: " + i["date"] + ", Nota: " + msg.decode("latin-1") + "\n"
                cont += 1

        # Then it creates the note and places it (with the text that it has been accumulating)
        note = Label(self, text=notes, width=100)
        note.grid(row=1,column=4,pady=(50,5),padx=(20,1))
    
    # Function to delete the note with the date "date" of the user notes
    def delete(self, date, parent):
        
        # It opens the data.json to load the data
        with open("store_login/notes.json", "r") as outfile:
            data = json.load(outfile)
        
        # It declarates found to False to check if the note with that date is in the notes.json or not
        found = False
        for i in data:
            if i["user"] == self.user and i["date"] == date:

                # If the note with that date is in the notes.json it simply removes the note 
                data.remove(i)
                found = True
            
        # If found it dumps the new notes in the json (without the note with that date)
        if found:
            with open("store_login/notes.json", "w") as outfile2:
                json.dump(data, outfile2)

            # It calls to the show_note funtion to update the notes shown
            self.show_note(parent)

        # If the note with that date is not in the notes.json it will show an ERROR
        else:
            messagebox.showinfo(title="Delete Error",message="There is no note with the date: " + date)


#******************************************************************************************
# Class ShowNote
#******************************************************************************************
class MainPage(tk.Frame):
    """ This is the frame for the Main Page duty, this frame will only show buttons to go to the other frames """

    def __init__(self, parent, controller):
        
        # This will initialize the frame
        tk.Frame.__init__(self, parent)
        
        # User is none, to have the global user after this (we)
        self.user = None

        # The declaration of all the buttons in the main frame which will show the other frames
        note_butt = tk.Button(self, text="Add note/edit note", width=20, height=3,
                                command=lambda:controller.show_frame(WriteNote,self.user))

        note_butt1 = tk.Button(self, text="Show notes", width=20, height=3,
                                command=lambda:controller.show_frame(ShowNote,self.user))
        
        note_butt2 = tk.Button(self, text="Delete note", width=20, height=3,
                                command=lambda:controller.show_frame(DeleteNote,self.user))
                                
        back_butt = tk.Button(self, text="Cerrar sesión", width=20, height=2, command=lambda:controller.show_frame(Home))
        
        
        
        # It places all the buttons
        note_butt.grid(row=0, column=4,pady=(10,10),padx=200)
        note_butt1.grid(row=2, column=4,pady=(10,10),padx=200)
        note_butt2.grid(row=4, column=4,pady=(10,10),padx=200)
        back_butt.grid(row=6, column= 4, pady=(10,10),padx=200)


# It initializates the App to mainloop it
app = MyApp()
app.mainloop()  
