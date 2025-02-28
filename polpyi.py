import time
import hashlib
import json
import random
import sympy
import socket
import threading
import tkinter as tk
from collections import defaultdict
from threading import Thread, Lock

# --- Хеширование ---
def simple_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

# --- Генерация ключей RSA ---
def generate_keys(bits=512):
    p, q = sympy.randprime(2**(bits-1), 2**bits), sympy.randprime(2**(bits-1), 2**bits)
    n, phi = p * q, (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi)
    return ((e, n), (d, n))

# --- Запуск P2P-сервера ---
def start_p2p_server(blockchain, host='0.0.0.0', port=5000):
    def handle_client(conn):
        data = conn.recv(1024).decode()
        if data:
            tx_data = json.loads(data)
            tx_data.pop("tx_hash", None)  # Удаляем tx_hash перед созданием объекта
            transaction = Transaction(**tx_data)
            blockchain.add_block([transaction])
            blockchain.gui.update_display()  # Автообновление GUI
        conn.close()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen()
        print("P2P сервер запущен...")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn,)).start()

# --- Меркле Дерево ---
class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_merkle_root()
    
    def build_merkle_root(self):
        if not self.transactions:
            return None
        tx_hashes = [simple_hash(tx.to_dict()) for tx in self.transactions]
        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 != 0:
                tx_hashes.append(tx_hashes[-1])
            tx_hashes = [simple_hash(tx_hashes[i] + tx_hashes[i+1]) for i in range(0, len(tx_hashes), 2)]
        return tx_hashes[0]


# --- Класс Blockchain с PoW и разрешением конфликтов ---
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.balances = defaultdict(lambda: 100)
        self.peers = set()
        self.mining_reward = 50  # Награда за майнинг

    def create_genesis_block(self):
        return Block(0, "0", [])
    
    def add_block(self, transactions, miner_address="Miner1"):
        prev_block = self.chain[-1]
        reward_tx = Transaction("Network", miner_address, self.mining_reward, 0)
        transactions.append(reward_tx)
        new_block = Block(len(self.chain), prev_block.hash, transactions)
        self.chain.append(new_block)
        for tx in transactions:
            self.balances[tx.sender] -= tx.amount
            self.balances[tx.receiver] += tx.amount
    
    def get_balance(self, user):
        return self.balances[user]
    
    def resolve_conflicts(self, new_chain):
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            print("Конфликт решен: принята более длинная цепочка")
    
    def register_peer(self, peer_address):
        self.peers.add(peer_address)
    
    def broadcast_transaction(self, transaction):
        for peer in self.peers:
            self.send_data(peer, json.dumps(transaction.to_dict()))
    
    def send_data(self, peer, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer, 5000))
                s.sendall(data.encode())
        except Exception as e:
            print(f"Ошибка отправки данных на {peer}: {e}")

# --- Класс Block (с PoW) ---
class Block:
    def __init__(self, index, previous_hash, transactions, difficulty=3):
        self.index = index
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.merkle_root = MerkleTree(transactions).root
        self.nonce, self.hash = self.mine_block(difficulty)
    
    def mine_block(self, difficulty):
        nonce = 0
        while True:
            block_string = f"{self.index}{self.previous_hash}{self.merkle_root}{nonce}"
            block_hash = hashlib.sha256(block_string.encode()).hexdigest()
            if block_hash[:difficulty] == '0' * difficulty:
                return nonce, block_hash
            nonce += 1

# --- Класс Transaction ---
class Transaction:
    def __init__(self, sender, receiver, amount, fee=0):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.fee = fee
        self.tx_hash = self.calculate_hash()
    
    def calculate_hash(self):
        return simple_hash(self.to_dict(include_hash=False))
    
    def to_dict(self, include_hash=True):
        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "fee": self.fee
        }
        if include_hash:
            data["tx_hash"] = self.tx_hash
        return data

# --- BlockchainGUI: Улучшенный интерфейс ---
class BlockchainGUI:
    def __init__(self, root, blockchain, wallet):
        self.blockchain = blockchain
        self.wallet = wallet
        self.user = "User1"
        self.root = root
        self.root.title("Blockchain Explorer & Wallet")
        self.blockchain.gui = self  # Ссылка для автообновления
        
        # Основной фрейм
        self.main_frame = tk.Frame(root, padx=10, pady=10)
        self.main_frame.pack()

        # Баланс и выбор пользователя
        self.top_frame = tk.Frame(self.main_frame)
        self.top_frame.pack(fill=tk.X)

        self.balance_label = tk.Label(self.top_frame, text=f"Баланс: {self.blockchain.get_balance(self.user)}", font=("Arial", 12, "bold"))
        self.balance_label.pack(side=tk.LEFT, padx=10)
        
        self.user_label = tk.Label(self.top_frame, text="Выберите пользователя:")
        self.user_label.pack(side=tk.LEFT, padx=10)
        
        self.user_list = tk.Listbox(self.top_frame, height=3, exportselection=False)
        for user in ["User1", "User2", "User3"]:
            self.user_list.insert(tk.END, user)
        self.user_list.pack(side=tk.LEFT)
        self.user_list.bind("<<ListboxSelect>>", self.change_user)
        
        # Текстовое поле для блокчейна
        self.text = tk.Text(self.main_frame, height=20, width=80, font=("Courier", 10))
        self.text.pack()
        
        # Подключенные узлы
        self.peer_label = tk.Label(self.main_frame, text="Подключенные узлы:")
        self.peer_label.pack()
        self.peer_list = tk.Listbox(self.main_frame, height=5)
        self.peer_list.pack()
        
        self.peer_entry = tk.Entry(self.main_frame)
        self.peer_entry.pack()
        self.connect_button = tk.Button(self.main_frame, text="Подключиться к узлу", command=self.connect_to_peer)
        self.connect_button.pack()
        
        # Кнопка отправки транзакции
        self.send_button = tk.Button(self.main_frame, text="Отправить транзакцию", font=("Arial", 12, "bold"), bg="green", fg="white", command=self.send_transaction)
        self.send_button.pack(pady=5)
        
        # Кнопка выхода
        self.exit_button = tk.Button(self.main_frame, text="Выход", font=("Arial", 12, "bold"), bg="red", fg="white", command=root.quit)
        self.exit_button.pack(pady=5)
        
        self.update_display()
    
    def send_transaction(self):
        sender = self.user
        receiver = "User2" if self.user == "User1" else "User1"
        amount = 10
        fee = 1
        tx = Transaction(sender, receiver, amount, fee)
        self.blockchain.add_block([tx])
        self.blockchain.broadcast_transaction(tx)
        self.update_display()
    
    def connect_to_peer(self):
        peer = self.peer_entry.get()
        if peer:
            self.blockchain.register_peer(peer)
            self.update_display()
    
    def change_user(self, event):
        selected = self.user_list.curselection()
        if selected:
            self.user = self.user_list.get(selected[0])
            self.update_display()
    
    def update_display(self):
        self.text.delete(1.0, tk.END)
        self.balance_label.config(text=f"Баланс: {self.blockchain.get_balance(self.user)}")
        self.peer_list.delete(0, tk.END)
        for peer in self.blockchain.peers:
            self.peer_list.insert(tk.END, peer)
        for block in self.blockchain.chain:
            self.text.insert(tk.END, f"Index: {block.index}\n")
            self.text.insert(tk.END, f"Previous Hash: {block.previous_hash}\n")
            self.text.insert(tk.END, f"Merkle Root: {block.merkle_root}\n")
            self.text.insert(tk.END, f"Nonce: {block.nonce}\n")
            self.text.insert(tk.END, f"Hash: {block.hash}\n")
            for tx in block.transactions:
                self.text.insert(tk.END, f"Tx: {tx.sender} -> {tx.receiver} : {tx.amount} coins (Fee: {tx.fee})\n")
            self.text.insert(tk.END, "----------------------\n")

# --- Запуск ---
if __name__ == "__main__":
    blockchain = Blockchain()
    wallet = generate_keys()
    threading.Thread(target=start_p2p_server, args=(blockchain,), daemon=True).start()
    root = tk.Tk()
    gui = BlockchainGUI(root, blockchain, wallet)
    root.mainloop()

