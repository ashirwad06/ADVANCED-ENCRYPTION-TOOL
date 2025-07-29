import os
import base64
from tkinter import filedialog, messagebox, Tk, Label, Button, Entry
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import padding

backend = default_backend()

# Generate AES-256 key using password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        output_path = file_path + ".enc"
        with open(output_path, 'wb') as f:
            f.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted and saved as:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()

        salt = file_data[:16]
        iv = file_data[16:32]
        encrypted_data = file_data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        output_path = file_path.replace(".enc", "") + "_decrypted"
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted and saved as:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI
class AESApp:
    def __init__(self, master):
        self.master = master
        master.title("AES-256 File Encryption Tool")
        master.geometry("400x230")
        master.resizable(False, False)

        self.label = Label(master, text="Enter Password:")
        self.label.pack(pady=5)

        self.password_entry = Entry(master, show="*", width=40)
        self.password_entry.pack(pady=5)

        self.select_button = Button(master, text="Select File", command=self.select_file)
        self.select_button.pack(pady=5)

        self.encrypt_button = Button(master, text="Encrypt File", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = Button(master, text="Decrypt File", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

        self.file_path = ""

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            messagebox.showinfo("File Selected", self.file_path)

    def encrypt(self):
        password = self.password_entry.get()
        if not self.file_path or not password:
            messagebox.showwarning("Input Missing", "Please select a file and enter a password.")
            return
        encrypt_file(self.file_path, password)

    def decrypt(self):
        password = self.password_entry.get()
        if not self.file_path or not password:
            messagebox.showwarning("Input Missing", "Please select a file and enter a password.")
            return
        decrypt_file(self.file_path, password)

if __name__ == "__main__":
    root = Tk()
    app = AESApp(root)
    root.mainloop()
