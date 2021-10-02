import tkinter

ventana = tkinter.Tk()
ventana.geometry("600x600")
ventana.configure(bg="grey")



space = tkinter.Label(height=5, bg="grey",)
space2 = tkinter.Label(height=5,bg="grey")
login_butt = tkinter.Button(ventana, text="Login", width=20, height=2)
sign_up_butt = tkinter.Button(ventana, text = "Sign Up", width=20, height=2)

space.pack()
login_butt.pack()
space2.pack()
sign_up_butt.pack()


ventana.mainloop()