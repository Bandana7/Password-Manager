from tkinter import *
from functools import partial
import sqlite3
import hashlib
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class GUIManager:
    def __init__(self, root):
        self.root = root
        self.encryption_key = None


    def destroy_widgets(self):
        try:
            for widget in self.root.winfo_children():
                widget.destroy()
        except TclError:
            pass


    def show_message(self, text):
        label = Label(self.root, text=text)
        label.pack(pady=5)

#Cryptographic setup
backend = default_backend()
salt = b'2554'

kdf = PBKDF2HMAC (    
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

#database setup
with sqlite3.connect("passwordmanager.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(id INTEGER PRIMARY KEY,password TEXT NOT NULL,recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY,website TEXT NOT NULL,username TEXT NOT NULL,password TEXT NOT NULL);
""")

#GUI setup
root = Tk ()
root.title("Password Manager")
root.configure(bg="lightblue")
gui_manager = GUIManager(root)

#creating popup
def popUp(text,is_password=False):
    popup = Toplevel(root)
    popup.title("Input")
    popup.geometry("300x100")
    
    label = Label(popup, text=text)
    label.pack(pady=5)
    
    entry = Entry(popup, show="*")  if is_password else Entry(popup)#to hide the password when written * is used
    entry.pack(pady=5)
    
    answer = None

    def save():
        nonlocal answer
        answer = entry.get()
        popup.destroy()

    btn = Button(popup, text="Save", command=save)
    btn.pack(pady=5)

    popup.wait_window()
    return answer

# Hashing Password
def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

#First Screen
def firstScreen(root):
    gui_manager.destroy_widgets()
    if root:

        root.configure(bg="lightblue")
    fheading = Label(root, text="Password Manager", width=40, bg="lightblue", font="Ariel 14 bold", padx=10, pady=10)
    fheading.grid(pady=10)

    lbl = Label(root, text="Create Master Password",font="Ariel 13")
    lbl.config(anchor=CENTER)
    lbl.grid(row=1,padx=5,pady=5)

    txt= Entry(root, width=30, show="*") 
    txt.grid(row=2,padx=5,pady=5)
    txt.focus() #to only focus on texts

    lbl1 = Label(root,text="Re-enter Password",font="Ariel 13")
    lbl.config(anchor=CENTER)
    lbl1.grid(row=3,padx=5,pady=5)
    
    txt1= Entry(root, width=30, show="*") 
    txt1.grid(row=4,padx=5,pady=5)
    txt1.focus()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1" #deletes old password when creating a new one
            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            #for recovery key it generates random key
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password,recoveryKey)
            VALUES(?,?)"""
            cursor.execute(insert_password,((hashedPassword),(recoveryKey)))
            db.commit() 

            recoveryScreen(key)
        else:
            lbl.config(text="Passwords donot match")

    btn = Button(root, text="Save", command=savePassword)
    btn.grid(pady=10)

#Recovery Screen
def recoveryScreen(key):
    gui_manager.destroy_widgets()
    
    fheading = Label(root, text="Password Manager", width=40, bg="lightblue", font="Ariel 14 bold", padx=10, pady=5)
    fheading.grid(pady=10)

    lbl = Label(root, text="Save this key to recover account.", bg="lightblue",font="Ariel 14 bold")
    lbl.config(anchor=CENTER)
    lbl.grid(row=1,padx=5,pady=5)

    lbl1 = Label(root,text=key,font="Ariel 13")
    lbl1.grid(row=3,padx=5,pady=5)

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))
    
    btn = Button(root, text="Copy", command=copyKey)
    btn.grid(row=5,pady=5)

    def done():
        passwordManager()

    btn = Button(root, text="Done", command=done)
    btn.grid(row=6,pady=10)

#Reset Screen
def resetScreen():
    gui_manager.destroy_widgets()

    fheading = Label(root, text="Password Manager", width=40, bg="lightblue", font="Ariel 14 bold", padx=10, pady=10)
    fheading.grid(pady=10)

    lbl = Label(root, text="Enter Key",bg="lightblue",font="Ariel 13 bold")
    lbl.config(anchor=CENTER)
    lbl.grid(row=1,padx=5,pady=5)

    txt= Entry(root, width=30) 
    txt.grid(row=2)

    lbl1 = Label(root)
    lbl1.config(anchor=CENTER)
    lbl1.grid(row=3)

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoverykey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()
    
    def checkRecoveryKey():
        checked = getRecoveryKey()
        
        if checked:
            firstScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong key",font="Ariel 13")

    btn = Button(root, text="Check", command=checkRecoveryKey)
    btn.grid(row=7,pady=10)

#Login Screen
def loginScreen(root):
    gui_manager.destroy_widgets()

    fheading = Label(root, text="Password Manager", width=40, bg="lightblue", font="Ariel 14 bold", padx=10, pady=10)
    fheading.grid(pady=10)

    lbl = Label(root, text="Enter Master Password",font="Ariel 13")
    lbl.config(anchor=CENTER)
    lbl.grid(row=1,padx=5,pady=5)

    txt= Entry(root, width=30, show="*") 
    txt.grid(row=2)

    lbl1 = Label(root)
    lbl1.grid

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()
    
    def checkPassword():
        match = getMasterPassword()
        
        #will redirect to another page password manager
        if match:
            passwordManager()
        else:
            txt.delete(0, 'end') #using "end" to delete written text after submission
            lbl1.config(text="Wrong Password")
            lbl1.grid(row=5)
    
    def resetPassword():
        resetScreen()

    btn = Button(root, text="Submit", command=checkPassword)
    btn.grid(row=3,pady=10)

    btn = Button(root, text="Reset Password", command=resetPassword)
    btn.grid(row=4,pady=10)

#Password Manager
#after entering the correct password it will bring the user to this page
def passwordManager():
    gui_manager.destroy_widgets()
    heading = Label(root, text="Password Manager", bg="lightblue", font="Ariel 14 bold", padx=10, pady=10)
    heading.config(anchor=CENTER)
    heading.grid(row=0, column=0, columnspan=3, padx=30, pady=10,sticky="nsew")
    
    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = encrypt(popUp(text1).encode(),encryptionKey)
        username = encrypt(popUp(text2).encode(),encryptionKey)
        password = encrypt(popUp(text3, is_password=True).encode(),encryptionKey)
        insert_fields = """INSERT INTO vault(website,username,password)
            VALUES(?,?,?)"""

        cursor.execute(insert_fields,(website,username,password))
        db.commit()

        passwordManager()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordManager()

    def copyPassword(password):
        root.clipboard_clear()
        root.clipboard_append(decrypt(password, encryptionKey))
        root.update()
    
    def logout():
        loginScreen(root)

    root.geometry("800x500")
    root.configure(bg="lightblue")

    btn = Button(root, text="Add",width=15,font="Ariel 14 bold",bg="blue", command=addEntry) 
    btn.grid(row=2,column=0, padx=50,pady=10)   
    
    lbl = Label(root, text="Website",font="Ariel 12 bold",bg="lightblue")
    lbl.grid(row=3,column=0, pady=10)
    lbl = Label(root, text="Username",font="Ariel 12 bold", bg="lightblue")
    lbl.grid(row=3,column=1, padx=10,pady=10)
    lbl = Label(root, text="Password",font="Ariel 12 bold", bg="lightblue")
    lbl.grid(row=3,column=2, padx=10,pady=10)
    
    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if  (len(array) == 0):
                break

            lbl1 = Label(root, text=(decrypt(array[i][1],encryptionKey)), font="Ariel 12",width=20)
            lbl1.grid(column=0, row=i+4)
            lbl1 = Label(root, text=(decrypt(array[i][2],encryptionKey)), font="Ariel 12",width=20)
            lbl1.grid(padx=5,column=1, row=i+4)
            lbl1 = Label(root, text=(decrypt(array[i][3],encryptionKey)), font="Ariel 12",width=20)
            lbl1.grid(padx=5,column=2, row=i+4)

            btn_copy = Button(root, text="Copy",command=partial(copyPassword, array[i][3]))
            btn_copy.grid(column=3, row=i + 4, padx=5,pady=10)

            btn = Button(root,text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=4, row=i+4,padx=5, pady=10)

            i=i+1
            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break

    btn_logout = Button(root, text="Logout", bg="green",font="Arieal 10 bold",command=logout)
    btn_logout.grid(column=0, row=i + 5, pady=10, columnspan=4)

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen(root)
else:
    firstScreen(root)
root.mainloop()


    