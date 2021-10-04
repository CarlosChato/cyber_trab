import tkinter as tk

class MyApp(tk.Tk):
    def __init__(self, *args, **kwargs):

        tk.Tk.__init__(self, *args, **kwargs)

        container = tk.Frame(self, highlightcolor="red")
        container.pack( side = "top", fill = "both", expand = True )

        

        container.grid_rowconfigure(0,weight = 1)
        container.columnconfigure(0,weight = 1)

        self.frames = {}

        for F in (Home, LogIn, MainPage):#we have to set all the screens into ()
            
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

        login_butt.pack(pady=(200,10),padx=200) #padding 200px for top and 10 px for bot
        sign_up_butt.pack(pady=(10,200),padx=200) #padding like the last one, but inverse


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
        controller.show_frame(MainPage)

class MainPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        user = tk.Label(self, text="user", width=20, height=2)
        entry_name = tk.Entry(self,  width=40)
        password = tk.Label(self,text="password", width=20)
        entry_pass = tk.Entry(self,width=40,show="*")
       

        user.grid(row=0,column=1,pady=(50,5),padx=(20,1)) 
        entry_name.grid(row=0,column=4,pady=(50,5)) 
        password.grid(row=2,column=1,pady=(50,5),padx=(20,1))
        entry_pass.grid(row=2,column=4,pady=(50,5))
        




        

app = MyApp()
app.mainloop()  