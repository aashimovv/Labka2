import time
import random
import tkinter as tk
from threading import Thread, Lock
from sha256_custom import sha256  # Используем нашу реализацию SHA-256

# Глобальная переменная для хранения блокчейна
blockchain = []
lock = Lock()
miner_rewards = {"Miner1": 0, "Miner2": 0}  # Подсчет наград
mining_complete = False  # Флаг для остановки проигравшего майнера

# Константы
DIFFICULTY = 3  # Количество нулей в начале хэша
REWARD = 50  # Награда за блок

class Block:
    def __init__(self, index, previous_hash, transactions, miner, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.miner = miner
        self.nonce = nonce
        self.timestamp = time.time()
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = f"{self.index}{self.previous_hash}{self.transactions}{self.miner}{self.nonce}{self.timestamp}"
        return sha256(block_data)

    def mine_block(self):
        global mining_complete
        start_time = time.time()
        while not self.hash.startswith('0' * DIFFICULTY):
            if mining_complete:
                return None  # Выход из майнинга, если другой майнер уже добыл блок
            self.nonce += 1
            self.hash = self.calculate_hash()
        mining_time = time.time() - start_time
        print(f"Блок {self.index} найден {self.miner} за {mining_time:.2f} секунд")
        return self.hash

class Miner(Thread):
    def __init__(self, name):
        super().__init__()
        self.name = name
        self.block_found = None

    def run(self):
        global blockchain, mining_complete
        prev_block = blockchain[-1] if blockchain else None
        prev_hash = prev_block.hash if prev_block else "0" * 64
        fee = random.randint(1, 5)  # Случайная комиссия за транзакции
        transactions = [f"TX: Alice -> Bob {random.randint(1, 10)} coins", f"Reward -> {self.name} {REWARD + fee} coins"]
        new_block = Block(len(blockchain), prev_hash, transactions, self.name)
        
        print(f"{self.name} начал майнинг блока {new_block.index}...")
        block_hash = new_block.mine_block()

        if block_hash:
            with lock:
                if not mining_complete:
                    blockchain.append(new_block)
                    miner_rewards[self.name] += (REWARD + fee)
                    mining_complete = True  # Останавливаем второго майнера
                    print(f"{self.name} добыл блок {new_block.index} с хэшем {new_block.hash}")
        else:
            print(f"{self.name} не успел. Блок уже добавлен другим майнером.")

# Графический интерфейс
class BlockchainGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Mining Simulation")
        self.text = tk.Text(root, height=20, width=80)
        self.text.pack()
        self.update_gui()

    def update_gui(self):
        self.text.delete(1.0, tk.END)
        self.text.insert(tk.END, "Блокчейн:\n")
        for block in blockchain:
            self.text.insert(tk.END, f"Блок {block.index}:\n")
            self.text.insert(tk.END, f" - Хэш: {block.hash}\n")
            self.text.insert(tk.END, f" - Майнер: {block.miner}\n")
            self.text.insert(tk.END, f" - Награда: {REWARD} + комиссия\n")
        self.text.insert(tk.END, "\nНаграды майнеров:\n")
        for miner, reward in miner_rewards.items():
            self.text.insert(tk.END, f"{miner}: {reward} coins\n")

# Запуск майнинга в фоне
def start_mining():
    global mining_complete
    mining_complete = False  # Сбрасываем флаг перед началом нового майнинга
    
    miner1 = Miner("Miner1")
    miner2 = Miner("Miner2")
    miner1.start()
    miner2.start()
    miner1.join()
    miner2.join()
    app.update_gui()  # Обновляем GUI после завершения майнинга

# Запуск GUI сразу
root = tk.Tk()
app = BlockchainGUI(root)

# Запускаем майнинг в фоновом потоке
mining_thread = Thread(target=start_mining)
mining_thread.start()

root.mainloop()
