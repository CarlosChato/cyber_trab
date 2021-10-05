import tkinter as tk
import json 
from tkinter import messagebox

class MainPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)