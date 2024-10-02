import socket
import threading
import os
import subprocess
import sys
import base64
import time
from stem.control import Controller
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import json

# Global variables
target_ip = ''
target_port = 0
target_public_key = None
private_key = None
aes_key = None

# Function to display ASCII banner after connection
def display_banner():
    print(r"""
 ___________________________________________________________________________________________________         
|\   ____\|\  \|\  \     |\  ___ \ |\   ___  \|\___   ___\\   _ \  _   \|\   __  \|\   ___ \|\  ___ \         
\ \  \___|\ \  \ \  \    \ \   __/|\ \  \\ \  \|___ \  \_\ \  \\\__\ \  \ \  \|\  \ \  \_|\ \ \   __/|        
 \ \_____  \ \  \ \  \    \ \  \_|/_\ \  \\ \  \   \ \  \ \ \  \\|__| \  \ \  \\\  \ \  \ \\ \ \  \_|/__      
  \|____|\  \ \  \ \  \____\ \  \_|\ \ \  \\ \  \   \ \  \ \ \  \    \ \  \ \  \\\  \ \  \_\\ \ \  \_|\ \     
    ____\_\  \ \__\ \_______\ \_______\ \__\\ \__\   \ \__\ \ \__\    \ \__\ \_______\ \_______\ \_______\    
   |\_________\|__|\|_______|\|_______|\|__| \|__|    \|__|  \|__|     \|__|\|_______|\|_______|\|_______|    
   \|_________|                                                                                                                                                           

                     SilentMode v1.0.0
 ___________________________________________________________
""")

# Function to install required packages if missing
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def install_dependencies():
    packages = ['stem', 'cryptography']
    for package in packages:
        try:
            __import__(package)
        except ImportError:
            install_package(package)

# Function to generate AES key based on password
def generate_aes_key(password):
    salt = os.urandom(16)  # Generate random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# AES encryption/decryption
def encrypt_aes(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes(ciphertext, key):
    try:
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext[16:]) + decryptor.finalize().decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# RSA encryption/decryption
def encrypt_aes_key(aes_key, public_key):
    ciphertext = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_aes_key(encrypted_aes_key, private_key):
    encrypted_aes_key = base64.b64decode(encrypted_aes_key)
    return private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key



# Send/handle chat request
def send_chat_request(target_username, target_ip, target_port, aes_key):
    encrypted_aes_key = encrypt_aes_key(aes_key, target_public_key)
    request_message = f"CHAT_REQUEST:{target_username}:{encrypted_aes_key}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((target_ip, target_port))
            client_socket.sendall(request_message.encode())
        print(f"Chat request sent to user {target_username}.")
    except Exception as e:
        print(f"Error sending chat request: {e}")

def handle_chat_request(client_socket):
    with client_socket:
        while True:
            try:
                request_msg = client_socket.recv(1024).decode()
                if not request_msg:
                    break
                if request_msg.startswith("CHAT_REQUEST:"):
                    parts = request_msg.split(":")
                    requester = parts[1]
                    encrypted_aes_key = parts[2]
                    print(f"Received chat request from {requester}.")
                    
                    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
                    
                    response = input("Type 'accept' to accept, 'reject' to reject: ").lower()
                    if response == 'accept':
                        print(f"Chat accepted with {requester}.")
                        threading.Thread(target=chat_interface, args=(requester, aes_key)).start()
                    else:
                        print(f"You rejected the chat request from {requester}.")
            except Exception as e:
                print(f"Error processing request: {e}")
                break

# Chat interface and message send/receive functions
def chat_interface(username, aes_key):
    print(f"\nWelcome to SilentMode Chat, {username}!")
    print("You are now connected.")
    
    threading.Thread(target=receive_messages, args=(aes_key,)).start()

    while True:
        message = input("You: ")
        if message.lower() == 'exit':
            print("Exiting chat...")
            break
        
        encrypted_message = encrypt_aes(message, aes_key)
        send_message_func(encrypted_message)

def send_message_func(message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((target_ip, target_port))
            client_socket.sendall(message.encode())
    except Exception as e:
        print(f"Error sending message: {e}")

def receive_messages(aes_key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind(('', target_port))
            server_socket.listen(1)
            print(f"Waiting for incoming messages on port {target_port}...")
            client_socket, _ = server_socket.accept()
            with client_socket:
                while True:
                    data = client_socket.recv(1024).decode()
                    if data:
                        decrypted_message = decrypt_aes(data, aes_key)
                        print(f"Received: {decrypted_message}")
    except Exception as e:
        print(f"Error receiving message: {e}")

# Start server and rotate keys
def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen(5)
    print(f"Listening for connections on port {port}...")
    
    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_chat_request, args=(client_socket,)).start()

def rotate_keys():
    global aes_key, salt
    while True:
        time.sleep(300)
        password = getpass("Enter your password to rotate the AES key: ")
        aes_key, salt = generate_aes_key(password)
        print("AES key rotated successfully.")

# Main function
def main():
    install_dependencies()
    display_banner()
    
    global private_key, target_public_key
    private_key, target_public_key = generate_rsa_keys()

    global target_ip, target_port
    target_username = input("Enter the target username: ")
    target_ip = input("Enter the target IP: ")
    target_port = int(input("Enter the target port: "))
    
    password = getpass("Enter your password: ")
    global aes_key, salt
    aes_key, salt = generate_aes_key(password)
    


    # Start the server in a separate thread to handle incoming requests
    threading.Thread(target=start_server, args=(target_port,)).start()

    # Start key rotation in a separate thread
    threading.Thread(target=rotate_keys, daemon=True).start()

    # Send chat request to the target user
    send_chat_request(target_username, target_ip, target_port, aes_key)

if __name__ == "__main__":
    main()
