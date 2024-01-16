import tkinter as tk
from func import decrypt, encrypt

def encrypt_text():
    text = plaintext_input.get()
    password = password_input.get()

    encrypted_text = encrypt(plaintext=text, password=password)

    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    try:
        result_text.insert(tk.END, f"{encrypted_text.decode('utf-8')}\n")
    except:
        result_text.insert(tk.END, f"Error encrypting\n")
    result_text.config(state=tk.DISABLED)

def decrypt_text():
    text = plaintext_input.get()
    password = password_input.get()

    decrypted_text = decrypt(encrypted_text=text, password=password)

    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    try:
        result_text.insert(tk.END, f"{decrypted_text.decode('utf-8')}\n")
    except:
        result_text.insert(tk.END, f"Error decrypting\n")

    result_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    window = tk.Tk()
    window.title("Encrypt Program")
    window.geometry("400x300")

    plaintext_label = tk.Label(window, text="Text:")
    plaintext_label.pack()

    plaintext_input = tk.Entry(window)
    plaintext_input.pack()

    password_label = tk.Label(window, text="Password:")
    password_label.pack()

    password_input = tk.Entry(window)
    password_input.pack()

    encrypt_btn = tk.Button(window, text="Encrypt", command=encrypt_text)
    encrypt_btn.pack()
    encrypt_btn = tk.Button(window, text="Decrypt", command=decrypt_text)
    encrypt_btn.pack()

    result_text = tk.Text(window, state=tk.DISABLED)
    result_text.pack()

    window.mainloop()