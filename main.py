import tkinter as tk

class MyApp():
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.geometry("600x600")
        self.ventana.configure(bg="grey")
        #space = tkinter.Label(height=5, bg="grey",)
        #space2 = tkinter.Label(height=5,bg="grey")
        login_butt = tk.Button(self.ventana, text="Login", width=20, height=2)
        sign_up_butt = tk.Button(self.ventana, text = "Sign Up", width=20, height=2)

        #space.pack()
        login_butt.pack(pady=100)
        #space2.pack()
        sign_up_butt.pack(pady=10)

app = MyApp()
app.ventana.mainloop()  