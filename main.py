import tkinter as tk

class MyApp(tk.Tk):
    def __init__(self, *args, **kwargs):

        tk.Tk.__init__(self, *args, **kwargs)

        container = tk.Frame(self)
        container.pack(side = "top", fill = "both", expand = True)

        container.grid_rowconfigure(0,weight = 1)
        container.columnconfigure(0,weight = 1)

        self.frames = {}

        for F in (Home, LogIn):#we have to set all the screens into ()
            
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
        sign_up_butt = tk.Button(self, text = "Sign Up", width=20, height=2)

        login_butt.pack(pady=(200,10)) #padding 200px for top and 10 px for bot
        sign_up_butt.pack(pady=(10,200)) #padding like the last one, but inverse


class LogIn(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        name = tk.Label(self, text="Name", width=20, height=2)
        sign_up_butt2 = tk.Button(self, text = "Sign Up", width=20, height=2)

        name.pack() #padding 200px for top and 10 px for bot
        sign_up_butt2.pack() #padding like the last one, but inverse
        

app = MyApp()
app.mainloop()  