#libs
import winreg
import win32com.client
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QScrollArea
from PyQt6.QtCore import Qt
#native libs
from collections import Counter
import sys
import os
import pefile
import math
import hashlib
import struct
from datetime import datetime
import re

#--------------------------------------------STRINGS--------------------------------------------

PRINTABLE_RE = re.compile(rb"[ -~]{6,}")
UTF16_RE = re.compile(rb"(?:[A-Za-z0-9 ./\\:_\-]\x00){4,}")

def is_valid_string(s: str) -> bool:
    # precisa ter pelo menos uma letra
    if not re.search(r"[A-Za-z]", s):
        return False
    # evitar lixo tipo AAAAABBBBB
    if len(set(s)) < len(s) * 0.4:
        return False
    # evitar excesso de símbolos
    if re.search(r"[^\w\s./:\\\-]{4,}", s):
        return False
    return True

#--------------------------------------------PRINT--------------------------------------------

SECTION_TOTAL_SIZE = 50

def get_section_entry_str(name:str) -> str:
    each_side_amount = int((SECTION_TOTAL_SIZE - len(name))/2)
    increment = ""
    if (each_side_amount*2) + len(name) < SECTION_TOTAL_SIZE:
        increment = "-"
    each_side = "-"*each_side_amount
    out = each_side + increment + name + each_side + "\n"
    return out

def get_section_end_str() -> str:
    out = "-"*SECTION_TOTAL_SIZE + "\n"
    return out

#--------------------------------------------INFO--------------------------------------------

def _calculate_entropy(data) -> float:
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def get_entropys(pe:pefile.PE) -> str:
    out = ""
    for s in pe.sections:
        entropy = _calculate_entropy(s.get_data())
        section_name = s.Name.decode('utf-8', errors='ignore').split('\x00')[0]
        out += f"{section_name:<20} {entropy:>10.4f}\n"
    full_entropy = _calculate_entropy(pe.__data__)
    out += f"{'FILE ENTROPY':<20} {full_entropy:>10.4f}\n"
    return out

def get_iat(pe:pefile.PE) -> str:
    out = ""
    total = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            out += f"DLL: {entry.dll.decode()}\n"
            for imp in entry.imports:
                address = hex(imp.address)
                name = imp.name.decode() if imp.name else "Ordinal"
                out += f"\t{address}: {name}\n"
                total += 1
    out += f"TOTAL ENTRIES: {total}\n"
    return out

def read_pe_timestamp(file_path):
    with open(file_path, 'rb') as f:
        f.seek(60)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_offset + 8)
        return struct.unpack('<I', f.read(4))[0]

#--------------------------------------------INTERFACE--------------------------------------------

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
        self.resize(440, 700)
        self.setAcceptDrops(True)
        label_color = "white" if get_windows_theme() else "black"
        layout = QVBoxLayout()

        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)

        self.label = QLabel('Arraste o arquivo .exe aqui', self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet(f"""
            border: 2px dashed #aaa; 
            border-radius: 10px; 
            font-size: 13px; 
            font-family: 'Consolas', 'Courier New', monospace;
            color: {label_color};
            padding: 10px;
        """)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.label.setWordWrap(True)
        self.scroll.setWidget(self.label)

        self.setLayout(layout)
        layout.addWidget(self.scroll)

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

    def extract_strings(self, file_path:str, min_len:int=4) -> None:
        results = []
        with pefile.PE(file_path) as pe:
            for section in pe.sections:
                section_name = section.Name.strip(b'\x00')
                data = section.get_data()
                # ASCII
                for m in PRINTABLE_RE.finditer(data):
                    try:
                        s = m.group().decode("ascii")
                        if len(s) >= min_len and is_valid_string(s):
                            results.append({"f":section_name.decode("utf-8"), "s":s})
                    except UnicodeDecodeError:
                        continue
                # UTF-16LE
                for m in UTF16_RE.finditer(data):
                    try:
                        s = m.group().decode("utf-16le")
                        if len(s) >= min_len and is_valid_string(s):
                            results.append({"f":section_name.decode("utf-8"), "s":s})
                    except UnicodeDecodeError:
                        continue
        return results

    def analyze(self, file_path:str):
        self.label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        out = ""
        imphash = None
        md5 = None
        with pefile.PE(file_path) as pe:
            imphash = pe.get_imphash()
            md5 = hashlib.md5(pe.__data__).hexdigest()


            out += get_section_entry_str("INFO")
            creation_timestamp = read_pe_timestamp(file_path)
            creation_date = datetime.fromtimestamp(creation_timestamp).strftime('%d/%m/%Y %H:%M:%S')
            out += f"File: {os.path.basename(file_path)}\n"
            out += f"Creation TimeStamp: {creation_timestamp} ({creation_date})\n"
            out += f"MD5: {md5}\n"
            out += f"ImpHash: {imphash}\n"
            out += get_section_end_str()
            

            out += get_section_entry_str("ENTROPY")
            out += get_entropys(pe)
            out += get_section_end_str()


            out += get_section_entry_str("IAT")
            out += get_iat(pe)
            out += get_section_end_str()


            out += get_section_entry_str("STRINGS")
            strings = self.extract_strings(file_path)
            out += f"TOTAL STRINGS = {len(strings)}\n"
            for elem in strings:
                out += str(elem['f']) + " = '" + elem['s'] + "'\n"
            out += get_section_end_str()


        self.label.setText(out)
        print(out)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = ExeAnalyzer()
    ex.show()
    sys.exit(app.exec())