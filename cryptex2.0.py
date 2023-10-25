from tkinter import *
from tkinter import PhotoImage
import base64

import messagebox


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_and_encrypt_notes():
    title = entry_title.get()
    message = secret_text.get("1.0", END)
    master_key = entry_master_key.get()

    if len(title) == 0 or len(message) == 0 or len(master_key) == 0:
        messagebox.showerror("Error!", message="Enter all Value!")

    else:
        # encryption
        message_encrypt = encode(master_key, message)



        try:
            with open("my_secret.txt", mode="a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypt}")
        except FileNotFoundError:
            with open("my_secret.txt", mode="w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypt}")

        finally:
            entry_title.delete(first=0, last=END)
            secret_text.delete("1.0", END)
            entry_master_key.delete(first=0, last=END)

def decrypt_button():
    message_encrypted = secret_text.get("1.0", END)
    master_key = entry_master_key.get()

    try:

        if len(message_encrypted) == 0 or len(master_key) == 0:
            messagebox.showerror("Error!", "Enter all Value!")

        else:
            decrypted_message = decode(master_key, message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
    except:
        messagebox.showerror("Error!!", "Enter a Encrypted Message!!!")










window = Tk()
window.title("secret notes")
window.config(padx=50, pady=40)
FONT = ("verdana", 15, "normal")

# UI
photo = PhotoImage(file="top_secret.png")
label_image = Label(image=photo)
label_image.pack()




title_info_label = Label(text="Enter Your Title", font=FONT)
title_info_label.pack()

entry_title = Entry(width=30)
entry_title.pack()

enter_text_label = Label(text="Enter Your Secret Text",font=FONT)
enter_text_label.pack()

secret_text = Text()
secret_text.config(width=40, height=25, padx=20, pady=15)
secret_text.pack()

input_info_label = Label(text="Enter Your Master Key", font=FONT)
input_info_label.pack()

entry_master_key = Entry(width=30)
entry_master_key.pack()

save_button = Button(text="Save & Crypt", command=save_and_encrypt_notes)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt_button)
decrypt_button.pack()

window.mainloop()
