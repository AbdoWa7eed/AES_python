from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import numpy as np
import io

class ImageEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Image Encryption/Decryption Tool")
        master.geometry("500x600")
        master.configure(bg="#f0f0f0")

        # Style configuration
        self.style = ttk.Style()
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TRadiobutton", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 12))

        # Encryption key storage
        self.encryption_key = None
        self.iv_or_nonce = None
        self.encrypted_data = None  # Adding the encrypted_data variable

        # Create main frame
        self.main_frame = ttk.Frame(master, padding="20 20 20 20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(self.main_frame, text="Image Encryption/Decryption", 
                  font=("Arial", 16, "bold")).pack(pady=(0,20))

        # Mode selection
        ttk.Label(self.main_frame, text="Encryption Mode:", font=("Arial", 12)).pack(anchor="w")
        self.mode_frame = ttk.Frame(self.main_frame)
        self.mode_frame.pack(fill="x", pady=(0,10))
        
        self.mode_var = tk.StringVar(value="ECB")
        mode_options = ["ECB", "CBC", "CTR"]
        for mode in mode_options:
            ttk.Radiobutton(
                self.mode_frame, 
                text=mode, 
                variable=self.mode_var, 
                value=mode
            ).pack(side=tk.LEFT, padx=10)

        # Action selection
        ttk.Label(self.main_frame, text="Operation:", font=("Arial", 12)).pack(anchor="w")
        self.action_frame = ttk.Frame(self.main_frame)
        self.action_frame.pack(fill="x", pady=(0,10))
        
        self.action_var = tk.StringVar(value="Encrypt")
        action_options = ["Encrypt", "Decrypt"]
        for action in action_options:
            ttk.Radiobutton(
                self.action_frame, 
                text=action, 
                variable=self.action_var, 
                value=action
            ).pack(side=tk.LEFT, padx=10)

        # Image preview
        self.preview_label = ttk.Label(self.main_frame, text="No image selected")
        self.preview_label.pack(pady=(10,10))

        # Process button
        self.process_button = ttk.Button(
            self.main_frame, 
            text="Select Image", 
            command=self.load_image_for_encryption_or_decryption
        )
        self.process_button.pack(pady=(10,20), fill="x")

        # Status message
        self.status_var = tk.StringVar(value="")
        self.status_label = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var, 
            foreground="green"
        )
        self.status_label.pack(pady=(10,0))

    def add_noise_to_image(self, image_data, noise_level=0.1):
        # Convert data to a numpy array
        image_array = np.frombuffer(image_data, dtype=np.uint8)
        
        # Specify image size as 256x256 RGB (you can change the size if needed)
        size = (256, 256)
        image_array = np.pad(image_array, (0, size[0] * size[1] * 3 - len(image_array)), 'constant')  # Ensure size matches
        image_array = image_array[:size[0] * size[1] * 3]  # Trim data to match required size
        image_array = image_array.reshape(size[0], size[1], 3)

        # Add random noise
        noise = np.random.normal(0, 255 * noise_level, image_array.shape).astype(np.uint8)
        noisy_image_array = np.clip(image_array + noise, 0, 255)  # Add noise while ensuring values are between 0 and 255

        # Convert the array back to an image
        noisy_image = Image.fromarray(noisy_image_array.astype(np.uint8))
        return noisy_image

    def encrypt_image(self, image_path, mode):
        # Open the image and convert it to bytes
        with open(image_path, "rb") as image_file:
            image_data = image_file.read()

        # Generate a random key each time
        key = get_random_bytes(16)  # AES 128-bit key

        # Check the encryption mode
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            # Ensure padding is added correctly
            padded_data = pad(image_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            return encrypted_data, cipher, key, None  # IV not required for ECB

        elif mode == "CBC":
            iv = get_random_bytes(16)  # Initialization vector for CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)
            # Ensure padding is added correctly
            padded_data = pad(image_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            return encrypted_data, cipher, key, iv  # Return encrypted data, IV, and key

        elif mode == "CTR":
            nonce = get_random_bytes(8)  # Nonce for CTR mode (should be 8 bytes only)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            encrypted_data = cipher.encrypt(image_data)  # Padding not required in CTR
            return encrypted_data, cipher, key, nonce  # Return encrypted data, key, and nonce

        else:
            raise ValueError("Unsupported AES mode")

    def decrypt_image(self, encrypted_data, mode, key, iv_or_nonce=None):
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_data = cipher.decrypt(encrypted_data)
            # Ensure padding is removed correctly
            try:
                decrypted_data = unpad(decrypted_data, AES.block_size)
            except ValueError as e:
                raise ValueError("Invalid padding: " + str(e))
        elif mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv_or_nonce)
            decrypted_data = cipher.decrypt(encrypted_data)
            try:
                decrypted_data = unpad(decrypted_data, AES.block_size)
            except ValueError as e:
                raise ValueError("Invalid padding: " + str(e))
        elif mode == "CTR":
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv_or_nonce)
            decrypted_data = cipher.decrypt(encrypted_data)
        else:
            raise ValueError("Unsupported AES mode")

        return decrypted_data

    def save_encrypted_image_as_fake_image(self, encrypted_data):
        # Add noise to the encrypted data
        noisy_image = self.add_noise_to_image(encrypted_data)  

        # Save the noisy image
        encrypted_image_path = filedialog.asksaveasfilename(
            defaultextension=".png", 
            filetypes=[("PNG Files", "*.png")]
        )
        if encrypted_image_path:  # Check if the user selected a save location
            noisy_image.save(encrypted_image_path)
            
            # Update image preview
            img_tk = ImageTk.PhotoImage(noisy_image.resize((250, 250)))
            self.preview_label.configure(image=img_tk)
            self.preview_label.image = img_tk
            self.status_var.set(f"Image encrypted and saved to {encrypted_image_path}")

    def show_decrypted_image(self, decrypted_data):
        try:
            # Convert decrypted data to an image and display it
            decrypted_image = Image.open(io.BytesIO(decrypted_data))
            
            # Update image preview
            img_tk = ImageTk.PhotoImage(decrypted_image.resize((250, 250)))
            self.preview_label.configure(image=img_tk)
            self.preview_label.image = img_tk
            
            # Display success message
            self.status_var.set("Image decrypted successfully!")
            
            # Show the original image
            decrypted_image.show()
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def load_image_for_encryption_or_decryption(self):
        # Select the image path
        image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")]
        )
        if image_path:  # Check if the user selected a file
            # Choose encryption or decryption mode
            mode = self.mode_var.get()
            
            try:
                # If encryption is selected
                if self.action_var.get() == "Encrypt":
                    self.encrypted_data, cipher, key, iv_or_nonce = self.encrypt_image(image_path, mode)
                    self.encryption_key = key  # Save the key for later decryption
                    self.iv_or_nonce = iv_or_nonce  # Save IV or nonce depending on the mode
                    self.save_encrypted_image_as_fake_image(self.encrypted_data)  # Save the encrypted image
                # If decryption is selected
                elif self.action_var.get() == "Decrypt":
                    if not self.encrypted_data:
                        messagebox.showerror("Error", "No encrypted image data found")
                        return
                    decrypted_data = self.decrypt_image(self.encrypted_data, mode, self.encryption_key, self.iv_or_nonce)
                    self.show_decrypted_image(decrypted_data)
            
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptionApp(root)
    root.mainloop()
