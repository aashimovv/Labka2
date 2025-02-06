import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# Function to hash data
def hash_data(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()

# Generate RSA Key Pair
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Convert keys to PEM format
def serialize_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem

# Digital signature
def sign_data(private_key, data):
    return private_key.sign(
        json.dumps(data, sort_keys=True, default=str).encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

# Verify signature
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            json.dumps(data, sort_keys=True, default=str).encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except:
        return False

# Transaction Class
class Transaction:
    def __init__(self, sender, receiver, amount, private_key):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.tx_id = hash_data({"sender": sender, "receiver": receiver, "amount": amount})
        self.timestamp = time.time()
        self.signature = sign_data(private_key, self.to_dict())
    
    def to_dict(self):
        return {"sender": self.sender, "receiver": self.receiver, "amount": self.amount, "tx_id": self.tx_id, "timestamp": self.timestamp}

# Blockchain Class
class Blockchain:
    def __init__(self, initial_balance, system_private_key, system_public_key):
        self.chain = []
        self.utxo = defaultdict(int)
        self.create_genesis_block(initial_balance, system_private_key, system_public_key)
    
    def create_genesis_block(self, initial_balance, system_private_key, system_public_key):
        user_address = hash_data(system_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        # Set initial balance to UTXO for user address
        self.utxo[user_address] = initial_balance
        genesis_tx = Transaction("system", user_address, initial_balance, system_private_key)
        self.chain.append(self.create_block([genesis_tx]))
    
    def create_block(self, transactions):
        valid_transactions = []
        temp_utxo = self.utxo.copy()
        
        for tx in transactions:
            if temp_utxo[tx.sender] >= tx.amount:
                temp_utxo[tx.sender] -= tx.amount
                temp_utxo[tx.receiver] += tx.amount
                valid_transactions.append(tx)
        
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": [tx.to_dict() for tx in valid_transactions],
            "previous_hash": self.chain[-1]["hash"] if self.chain else "0",
        }
        block["hash"] = hash_data(block)
        if valid_transactions:
            self.utxo = temp_utxo
        return block
    
    def add_block(self, transactions):
        new_block = self.create_block(transactions)
        self.chain.append(new_block)
    
    def get_balance(self, address):
        return self.utxo.get(address, 0)

# Wallet GUI
class WalletGUI:
    def __init__(self, root, blockchain, private_key, public_key):
        self.root = root
        self.blockchain = blockchain
        self.private_key = private_key
        self.public_key = public_key
        self.address = hash_data(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        self.root.title("Blockchain Wallet")
        self.create_widgets()
        self.update_balance()  # Ensure balance is updated upon startup
    
    def create_widgets(self):
        frame = ttk.LabelFrame(self.root, text="Wallet", padding="10")
        frame.grid(row=0, column=0, padx=10, pady=10)
        
        ttk.Label(frame, text=f"Address: {self.address[:10]}...").grid(row=0, column=0, columnspan=2)
        self.balance_label = ttk.Label(frame, text="Balance: 0")  # Default text, will be updated
        self.balance_label.grid(row=1, column=0, columnspan=2)
        
        ttk.Label(frame, text="Receiver:").grid(row=2, column=0)
        self.receiver_entry = ttk.Entry(frame)
        self.receiver_entry.grid(row=2, column=1)
        
        ttk.Label(frame, text="Amount:").grid(row=3, column=0)
        self.amount_entry = ttk.Entry(frame)
        self.amount_entry.grid(row=3, column=1)
        
        ttk.Button(frame, text="Send", command=self.send_transaction).grid(row=4, column=0, columnspan=2)
    
    def update_balance(self):
        balance = self.blockchain.get_balance(self.address)
        self.balance_label.config(text=f"Balance: {balance}")
    
    def send_transaction(self):
        receiver = self.receiver_entry.get()
        amount = int(self.amount_entry.get())
        
        # Check if the balance is sufficient
        if self.blockchain.get_balance(self.address) >= amount:
            # Create and add the transaction
            tx = Transaction(self.address, receiver, amount, self.private_key)
            self.blockchain.add_block([tx])
            
            # Update balance in the UI
            self.update_balance()
            
            # Show success message
            messagebox.showinfo("Success", "Transaction Sent")
        else:
            # Show error message if balance is insufficient
            messagebox.showerror("Error", "Insufficient Balance")

# Initialize Blockchain and Wallet
private_key, public_key = generate_key_pair()
bc = Blockchain(initial_balance=100, system_private_key=private_key, system_public_key=public_key)  # Set initial balance to 100
root = tk.Tk()
gui = WalletGUI(root, bc, private_key, public_key)
root.mainloop()
    