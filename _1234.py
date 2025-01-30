import hashlib
import json
import time
from collections import defaultdict
import tkinter as tk
from tkinter import ttk

# Function to hash data
def hash_data(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

# Merkle Tree Implementation
def merkle_root(transactions):
    if not transactions:
        return hash_data("")
    
    tx_hashes = [hash_data(tx) for tx in transactions]
    
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])  # Duplicate last hash if odd number
        tx_hashes = [hash_data(tx_hashes[i] + tx_hashes[i + 1]) for i in range(0, len(tx_hashes), 2)]
    
    return tx_hashes[0]

# Transaction Structure
class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.tx_id = hash_data({"sender": sender, "receiver": receiver, "amount": amount})
        self.timestamp = time.time()
    
    def to_dict(self):
        return {"sender": self.sender, "receiver": self.receiver, "amount": self.amount, "tx_id": self.tx_id, "timestamp": self.timestamp}

# UTXO Model
class Blockchain:
    def __init__(self):
        self.chain = []
        self.utxo = defaultdict(int)
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_tx = Transaction("system", "user1", 100)
        self.utxo["user1"] = 100
        genesis_block = self.create_block([genesis_tx])
        self.chain.append(genesis_block)
    
    def create_block(self, transactions):
        valid_transactions = []
        temp_utxo = self.utxo.copy()
        
        for tx in transactions:
            if temp_utxo[tx.sender] >= tx.amount:
                temp_utxo[tx.sender] -= tx.amount
                temp_utxo[tx.receiver] += tx.amount
                valid_transactions.append(tx)
        
        merkle_root_hash = merkle_root([tx.to_dict() for tx in valid_transactions])
        
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": [tx.to_dict() for tx in valid_transactions],
            "merkle_root": merkle_root_hash,
            "previous_hash": self.chain[-1]["hash"] if self.chain else "0",
        }
        block["hash"] = hash_data(block)
        if valid_transactions:
            self.utxo = temp_utxo  # Update balances only if block is valid
        return block
    
    def add_block(self, transactions):
        new_block = self.create_block(transactions)
        self.chain.append(new_block)

    def display_chain(self):
        chain_data = []
        for block in self.chain:
            block_data = {
                "Index": block['index'],
                "Timestamp": block['timestamp'],
                "Previous Hash": block['previous_hash'],
                "Merkle Root": block['merkle_root'],
                "Hash": block['hash']
            }
            transactions_data = []
            for tx in block['transactions']:
                transactions_data.append({
                    "Sender": tx['sender'],
                    "Receiver": tx['receiver'],
                    "Amount": tx['amount'],
                    "Tx ID": tx['tx_id'],
                    "Timestamp": tx['timestamp']
                })
            block_data["Transactions"] = transactions_data
            chain_data.append(block_data)
        return chain_data

    def get_utxo(self):
        return self.utxo

# GUI for Blockchain
class BlockchainGUI:
    def __init__(self, root, blockchain):
        self.root = root
        self.blockchain = blockchain
        self.root.title("Blockchain Explorer")
        self.create_widgets()
    
    def create_widgets(self):
        self.create_blockchain_table()
        self.create_utxo_table()

    def create_blockchain_table(self):
        block_frame = ttk.LabelFrame(self.root, text="Blockchain", padding="10")
        block_frame.grid(row=0, column=0, padx=10, pady=10)

        columns = ["Index", "Timestamp", "Previous Hash", "Merkle Root", "Hash"]
        self.block_table = ttk.Treeview(block_frame, columns=columns, show="headings")
        for col in columns:
            self.block_table.heading(col, text=col)
        
        self.block_table.grid(row=0, column=0, sticky="nsew")
        self.populate_blockchain_table()

    def create_utxo_table(self):
        utxo_frame = ttk.LabelFrame(self.root, text="Current UTXO", padding="10")
        utxo_frame.grid(row=1, column=0, padx=10, pady=10)

        columns = ["User", "Balance"]
        self.utxo_table = ttk.Treeview(utxo_frame, columns=columns, show="headings")
        for col in columns:
            self.utxo_table.heading(col, text=col)
        
        self.utxo_table.grid(row=0, column=0, sticky="nsew")
        self.populate_utxo_table()

    def populate_blockchain_table(self):
        for block in self.blockchain.display_chain():
            self.block_table.insert("", "end", values=(block["Index"], block["Timestamp"], block["Previous Hash"], block["Merkle Root"], block["Hash"]))
            for tx in block["Transactions"]:
                self.block_table.insert("", "end", values=(f"  - {tx['Sender']} -> {tx['Receiver']} : {tx['Amount']}", tx["Tx ID"], tx["Timestamp"]))

    def populate_utxo_table(self):
        for user, balance in self.blockchain.get_utxo().items():
            self.utxo_table.insert("", "end", values=(user, balance))

# Example Usage
if __name__ == "__main__":
    bc = Blockchain()
    tx1 = Transaction("user1", "user2", 30)
    bc.add_block([tx1])
    
    root = tk.Tk()
    gui = BlockchainGUI(root, bc)
    root.mainloop()

