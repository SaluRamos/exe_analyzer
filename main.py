#libs
import winreg
import win32com.client
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt
#native libs
from collections import Counter
import sys
import os
import pefile
import math
import hashlib

def get_imphash(file_path):
    pe = pefile.PE(file_path)
    return pe.get_imphash()

def calculate_entropy(data):
    if not data:
        return 0.0
    counter = Counter(data)
    file_len = len(data)
    entropy = 0.0
    for count in counter.values():
        p_x = count / file_len
        entropy += - p_x * math.log2(p_x)
    return entropy

def print_iat(file_path):
    print(f"-------------------{os.path.basename(file_path)}-------------------")
    pe = pefile.PE(file_path)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"DLL: {entry.dll.decode()}")
            for imp in entry.imports:
                address = hex(imp.address)
                name = imp.name.decode() if imp.name else "Ordinal"
                print(f"  {address}: {name}")
    print(f"---------------------------------------------------------")

def get_windows_theme() -> bool:
    """Retorna True se for Dark Mode, False se for Light Mode"""
    try:
        registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        key = winreg.OpenKey(registry, r"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize")
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return value == 0
    except Exception:
        return False

def get_shortcut_target(shortcut_path):
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        return shortcut.Targetpath
    except Exception:
        return None

class ExeAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Exe analyzer')
        self.resize(400, 200)
        self.setAcceptDrops(True)
        is_dark = get_windows_theme()
        layout = QVBoxLayout()
        self.label = QLabel('Arraste o arquivo .exe aqui', self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text_color = "white" if is_dark else "black"
        self.label.setStyleSheet(f"""
            border: 2px dashed #aaa;
            border-radius: 10px;
            font-size: 16px;
            color: {text_color};
        """)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.label.setWordWrap(True)
        layout.addWidget(self.label)
        self.setLayout(layout)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        for file_path in files:
            if file_path.lower().endswith('.lnk'):
                target = get_shortcut_target(file_path)
                if target:
                    file_path = target
            if file_path.lower().endswith('.exe'):
                self.analyze(file_path)
            else:
                self.label.setText("Erro: Arraste apenas arquivos .exe")

    def analyze(self, file_path:str):
        print_iat(file_path)

        with open(file_path, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        entropy = calculate_entropy(data)
        try:
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
        except Exception:
            imphash = "N/A (Erro ao ler PE)"
        result = (f"File: {os.path.basename(file_path)}\n" +
                    f"MD5: {md5}\n" +
                    f"ImpHash: {imphash}\n" +
                    f"Entropy: {entropy:.4f}\n"
        )
        self.label.setText(result)
        print(result)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = ExeAnalyzer()
    ex.show()
    sys.exit(app.exec())