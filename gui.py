import customtkinter as ctk
from tkinter import messagebox
from password_manager import check_key,get_sites,decrypt_message_og,choice_1,new_key,encrypt_with_new_key,read_key,backup_passwords,write_file_atomic

def on_click(event,site):
    # Get the widget that triggered the event
    widget = event.widget
    # Show a messagebox with the text of the widget
    if(widget.cget("text")=="**********"):
        widget.config(text=decrypt_message_og(site))
    else:
        widget.config(text="**********")

def print_sites(frame):
    sites=get_sites()
    for i in range(0,len(sites)):
        label1 = ctk.CTkLabel(frame, text=f"{sites[i]}",font=(None,14))
        label1.grid(row=i, column=0,sticky="w")  # Place the label in column 0
        label2 = ctk.CTkLabel(frame, text=f"**********",font=(None,14))
        label2.grid(row=i, column=1,sticky="e")  # Place the label in column 1
        label2.bind("<Button-1>", lambda event, site=sites[i]: on_click(event, site))

def create_new_window():
    wrong_credentials_label=None
    global entry_site,entry_password,new_window
    def submit_new_window(site,password):
        global new_window
        nonlocal wrong_credentials_label
        if(site=="" or password==""):
            entry_site.delete(0,"end")
            entry_password.delete(0,"end")
            if(wrong_credentials_label is not None):
                wrong_credentials_label.destroy()
            wrong_credentials_label=ctk.CTkLabel(frame_new_window, text="Wrong credentials. Try again.",text_color="red")
            wrong_credentials_label.place(x=200,y=200)
            return
        if(wrong_credentials_label is not None):
                wrong_credentials_label.destroy()
        data_no,data_yes=choice_1(site,password)
        if (data_yes != None and data_no != None and data_yes != data_no):
            choice=messagebox.askquestion("Overwrite","Site already exist.Overwrite?",icon='warning')
            file_path=".\\password.txt"
            if(choice=='yes'):
                write_file_atomic(file_path, data_yes)
            elif(choice=='no'):
                write_file_atomic(file_path, data_no)
        for widget in cross_window.winfo_children():
           widget.destroy()
        new_window.destroy()
        root.attributes('-disabled', False)
        print_sites(cross_window)
    new_window =ctk.CTk()
    new_window.geometry("400x300")
    new_window.resizable(False, False)
    new_window.title("Add_new_site")
    new_window.bind('<Destroy>', lambda _: root.attributes('-disabled',False))  # Bind function to Destroy event
    root.attributes('-disabled', True)
    #site_name&password frame
    frame_new_window=ctk.CTkFrame(new_window)
    frame_new_window.pack(padx=15,pady=20,fill="both",expand=True)
    entry_site=ctk.CTkEntry(frame_new_window,placeholder_text="Site")
    entry_site.place(x=120,y=80)
    entry_password=ctk.CTkEntry(frame_new_window,placeholder_text="Password",show="*")
    entry_password.place(x=120,y=110)
    submit_button = ctk.CTkButton(frame_new_window, text="Submit", command=lambda :submit_new_window(entry_site.get(),entry_password.get()))
    submit_button.place(x=120,y=140)
    
    new_window.bind('<Return>',lambda _: submit_new_window(entry_site.get(),entry_password.get()))
    new_window.mainloop()

def modify_window():
    global entry_site,entry_password,modify_new_window
    wrong_credentials_label=None
    def submit_modify_window(site,password):
        global modify_new_window
        nonlocal wrong_credentials_label
        if(password==""):
            entry_site.delete(0,"end")
            entry_password.delete(0,"end")
            if(wrong_credentials_label is not None):
                wrong_credentials_label.destroy()
            wrong_credentials_label=ctk.CTkLabel(frame_modify_new_window, text="Password can't be null dummy",text_color="red")
            wrong_credentials_label.place(x=100,y=180)
            return
        data_no,data_yes=choice_1(site,password)
        if (data_yes is not None and data_no is not None):
            choice=messagebox.askquestion("Overwrite","Overwrite?",icon='warning')
            file_path=".\\password.txt"
            if(choice=='yes'):
                write_file_atomic(file_path, data_yes)
            elif(choice=='no'):
                write_file_atomic(file_path, data_no)
        for widget in cross_window.winfo_children():
           widget.destroy()
        modify_new_window.destroy()
        root.attributes('-disabled', False)
        print_sites(cross_window)
    modify_new_window =ctk.CTk()
    modify_new_window.geometry("400x300")
    modify_new_window.resizable(False, False)
    modify_new_window.title("Modify")
    modify_new_window.bind('<Destroy>', lambda _: root.attributes('-disabled',False))  # Bind function to Destroy event
    root.attributes('-disabled', True)
    #site_name&password frame
    frame_modify_new_window=ctk.CTkFrame(modify_new_window)
    frame_modify_new_window.pack(padx=15,pady=20,fill="both",expand=True)
    entry_site=ctk.CTkOptionMenu(frame_modify_new_window,values=get_sites(),fg_color="#3A3B3C",button_color="#3A3B3C",button_hover_color="#0C090A")
    entry_site.place(x=120,y=80)
    entry_password=ctk.CTkEntry(frame_modify_new_window,placeholder_text="Password",show="*")
    entry_password.place(x=120,y=110)
    submit_button = ctk.CTkButton(frame_modify_new_window, text="Submit", command=lambda :submit_modify_window(entry_site.get(),entry_password.get()))
    submit_button.place(x=120,y=140)
    
    modify_new_window.bind('<Return>',lambda _: submit_modify_window(entry_site.get(),entry_password.get()))
    modify_new_window.mainloop()

def delete_window():
    global entry_site,delete_new_window
    def submit_delete_window(site):
        global delete_new_window
        data_no,data_yes=choice_1(site,"")
        if (data_yes != None and data_no != None):
            choice=messagebox.askquestion("Delete","Delete?",icon='warning')
            file_path=".\\password.txt"
            if(choice=='yes'):
                # Find and remove the site entry properly
                sites = get_sites()
                if site in sites:
                    data_yes = []
                    from password_manager import decrypt_site_name
                    for line in data_no:
                        words = line.split()
                        if len(words) >= 6:
                            site_cipher = bytes.fromhex(words[0])
                            site_nonce = bytes.fromhex(words[1])
                            site_tag = bytes.fromhex(words[2])
                            decrypted = decrypt_site_name(site_cipher, site_nonce, site_tag)
                            if decrypted != site:
                                data_yes.append(line)
                        else:
                            # Legacy format check
                            try:
                                if bytes.fromhex(words[0]).decode('utf-8') != site:
                                    data_yes.append(line)
                            except:
                                data_yes.append(line)
                    write_file_atomic(file_path, data_yes)
            elif(choice=='no'):
                write_file_atomic(file_path, data_no)
        for widget in cross_window.winfo_children():
           widget.destroy()
        delete_new_window.destroy()
        root.attributes('-disabled', False)
        print_sites(cross_window)
    delete_new_window =ctk.CTk()
    delete_new_window.geometry("400x300")
    delete_new_window.resizable(False, False)
    delete_new_window.title("Delete")
    delete_new_window.bind('<Destroy>', lambda _: root.attributes('-disabled',False))  # Bind function to Destroy event
    root.attributes('-disabled', True)
    #site_name&password frame
    frame_delete_new_window=ctk.CTkFrame(delete_new_window)
    frame_delete_new_window.pack(padx=15,pady=20,fill="both",expand=True)
    entry_site=ctk.CTkOptionMenu(frame_delete_new_window,values=get_sites(),fg_color="#3A3B3C",button_color="#3A3B3C",button_hover_color="#0C090A")
    entry_site.place(x=120,y=90)
    submit_button = ctk.CTkButton(frame_delete_new_window, text="Delete", command=lambda :submit_delete_window(entry_site.get()))
    submit_button.place(x=120,y=130)
    
    delete_new_window.bind('<Return>',lambda _: submit_delete_window(entry_site.get()))
    delete_new_window.mainloop()


wrong_key_oldnew_label=None
def change_key_window():
    global change_key_new_window
    def submit_change_key_window(old_key, newkey):
        global wrong_key_oldnew_label
        if (old_key == "" or newkey == "" or len(newkey) < 8 or not check_key(old_key) or old_key == newkey):
            if wrong_key_oldnew_label != None:
                wrong_key_oldnew_label.destroy()
            entry_new_key.delete(0, "end")
            entry_old_key.delete(0, "end")
            wrong_key_oldnew_label = ctk.CTkLabel(frame_change_key_new_window, text="Wrong credentials. Try again.", text_color="red")
            wrong_key_oldnew_label.place(x=100, y=180)
            return
        if (wrong_key_oldnew_label != None):
            wrong_key_oldnew_label.destroy()
        encrypt_with_new_key(newkey)
        change_key_new_window.destroy()
        root.attributes('-disabled', False)
    change_key_new_window = ctk.CTk()
    change_key_new_window.geometry("400x300")
    change_key_new_window.resizable(False, False)
    change_key_new_window.title("Change key")
    root.attributes('-disabled', True)
    # site_name&password frame
    frame_change_key_new_window = ctk.CTkFrame(change_key_new_window)
    frame_change_key_new_window.pack(padx=15, pady=20, fill="both", expand=True)
    entry_old_key = ctk.CTkEntry(frame_change_key_new_window, placeholder_text="Old key", show="*")
    entry_old_key.place(x=120, y=70)
    entry_new_key = ctk.CTkEntry(frame_change_key_new_window, placeholder_text="New key...", show="*")
    entry_new_key.place(x=120, y=110)
    submit_button = ctk.CTkButton(frame_change_key_new_window, text="Submit", command=lambda: submit_change_key_window(entry_old_key.get(), entry_new_key.get()))
    submit_button.place(x=120, y=150)

    change_key_new_window.bind('<Destroy>', lambda _: root.attributes('-disabled', False))  # Bind function to Destroy event
    change_key_new_window.bind('<Return>', lambda _: submit_change_key_window(entry_old_key.get(), entry_new_key.get()))
    change_key_new_window.mainloop()


wrong_key_label=None

def submit_root_window(_=None):
    global wrong_key_label
    global cross_window,key
    user_input=entry_key.get()
    check=check_key(user_input)
    #print(user_input)
    if(check==True):
        key=read_key()
        #print(key)
        entry_key.destroy()  # Remove the entry_key widget
        submit_button.destroy()  # Remove the submit button
        if(wrong_key_label is not None): #check if wrong_label exists
            wrong_key_label.destroy()  # Remove the wrong key label
        root.update_idletasks()  # Update the window
        root.geometry("600x270")
        #titles frame
        sitename_title=ctk.CTkLabel(frame,text="Site Name",height=24,width=30,font=(None,16),fg_color="#292929",corner_radius=10)
        sitename_title.place(x=10, y=10)
        password_title=ctk.CTkLabel(frame,text="Password",height=24,width=30,font=(None,16),fg_color="#292929",corner_radius=10)
        password_title.place(x=280, y=10)
        #scrollable frame
        cross_window=ctk.CTkScrollableFrame(frame)
        cross_window.place(x=10, y=40,relwidth=0.63,relheight=0.7)
        cross_window.grid_columnconfigure(0,weight=0)
        cross_window.grid_columnconfigure(1,weight=100)
        #Add new site button
        new_site_button=ctk.CTkButton(master=frame,text="Add new site",command=lambda: create_new_window())
        new_site_button.place(x=420,y=40)
        #Add modify button
        modify_button=ctk.CTkButton(master=frame,text="Modify",command=lambda: modify_window())
        modify_button.place(x=420,y=85)
        #Add delete button
        delete_button=ctk.CTkButton(master=frame,text="Delete",command=lambda: delete_window())
        delete_button.place(x=420,y=128)
        #Add change key button
        change_key_button=ctk.CTkButton(master=frame,text="Change key",command=lambda: change_key_window())
        change_key_button.place(x=420,y=173)
        print_sites(cross_window)
        backup_passwords()
    elif(check==False):
        entry_key.delete(0,"end")
        if(wrong_key_label is not None):
           wrong_key_label.destroy()
        wrong_key_label = ctk.CTkLabel(frame, text="Wrong key. Try again.",text_color="red")
        wrong_key_label.place(relx=0.95,rely=0.95,anchor='e')

wrong_key_welcome_label=None
def welcome_root_window(_=None):
    global wrong_key_welcome_label,entry_key
    user_input=entry_key.get()
    reuser_input=reentry_key.get()
    if(user_input=="" or len(user_input)<8):
        entry_key.delete(0,"end")
        reentry_key.delete(0,"end")
        if(wrong_key_welcome_label is not None):
           wrong_key_welcome_label.destroy()
        wrong_key_welcome_label = ctk.CTkLabel(frame, text="Key must be at least 8 characters long.",text_color="red")
        wrong_key_welcome_label.place(relx=0.95,rely=0.95,anchor='e')
        return
    if(user_input!=reuser_input):
        entry_key.delete(0,"end")
        reentry_key.delete(0,"end")
        if(wrong_key_welcome_label is not None):
           wrong_key_welcome_label.destroy()
        wrong_key_welcome_label = ctk.CTkLabel(frame, text="Keys don't match. Try again.",text_color="red")
        wrong_key_welcome_label.place(relx=0.95,rely=0.95,anchor='e')
        return
    if(wrong_key_welcome_label is not None):
        wrong_key_welcome_label.destroy()
    new_key(user_input)
    submit_root_window()

#MainLoop
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

root=ctk.CTk()
root.geometry("400x300")
root.resizable(False, False)
root.title("EWR")

frame=ctk.CTkFrame(root)
frame.pack(pady=20,padx=15,fill="both",expand=True)

login_file_path=".\\login.txt"
with open(login_file_path, 'r') as file:
    login_data = file.readlines()
print(login_data)
if(login_data==[]):
    root.bind('<Return>', welcome_root_window)
    entry_key=ctk.CTkEntry(frame,placeholder_text="Enter your new key...",show="*")
    entry_key.place(x=190,y=80,anchor='n')
    reentry_key=ctk.CTkEntry(frame,placeholder_text="Re-enter key",show="*")
    reentry_key.place(x=190,y=115,anchor='n')
    submit_button = ctk.CTkButton(frame, text="Welcome", command=welcome_root_window)
    submit_button.place(x=190, y=150, anchor='n')
elif(login_data[0]=="logged_in\n"):
    root.bind('<Return>', submit_root_window)
    entry_key=ctk.CTkEntry(frame,placeholder_text="Enter your key...",show="*")
    entry_key.pack(pady=100,padx=95,fill="both")
    submit_button = ctk.CTkButton(frame, text="Submit", command=submit_root_window)
    submit_button.place(relx=0.5, y=140, anchor='n')
else: 
    exit()

root.mainloop()