import tkinter as tk

class MyApp():
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.geometry("600x600")
        self.ventana.configure(bg="grey")
        
        login_butt = tk.Button(self.ventana, text="Login", width=20, height=2)
        sign_up_butt = tk.Button(self.ventana, text = "Sign Up", width=20, height=2)

        login_butt.pack(pady=(200,10)) #padding 200px for top and 10 px for bot
        sign_up_butt.pack(pady=(10,200)) #padding like the last one, but inverse

app = MyApp()
app.ventana.mainloop()  