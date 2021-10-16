import tkinter as tk
import json 
from tkinter import messagebox
from main import SignUp

class MainPage(tk.Frame, SignUp):

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent)

        note_butt = tk.Button(self, text="Note", width=20, height=3,
                                command=lambda:controller.show_frame(WriteNote))


        note_butt.pack(pady=(200,10),padx=200) #padding 200px for top and 10 px for bot

        print(self._user)