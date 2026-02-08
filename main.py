#libs
import winreg
import win32com.client
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QScrollArea, QLineEdit
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

def get_entropys(pe: pefile.PE) -> str:
    table_style = "style='width: 100%; border-collapse: collapse; font-family: Consolas;'"
    out = f"<table {table_style}>"
    for s in pe.sections:
        entropy = _calculate_entropy(s.get_data())
        section_name = s.Name.decode('utf-8', errors='ignore').split('\x00')[0]
        out += (
            f"<tr>"
            f"<td style='padding: 2px 10px;'>{section_name}</td>"
            f"<td style='padding: 2px 10px; text-align: right;'>{entropy:.4f}</td>"
            f"</tr>"
        )
    full_entropy = _calculate_entropy(pe.__data__)
    out += (
        f"<tr>"
        f"<td style='padding: 4px 10px;'><b>FILE ENTROPY</b></td>"
        f"<td style='padding: 4px 10px; text-align: right;'><b>{full_entropy:.4f}</b></td>"
        f"</tr>"
    )
    out += "</table>"
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
        self.setMinimumWidth(440) 
        self.setMinimumHeight(500)
        self.setAcceptDrops(True)
        label_color = "white" if get_windows_theme() else "black"
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0) # Remove margens externas
        
        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        self.container = QWidget()
        self.container.setMinimumWidth(440)
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setContentsMargins(5, 5, 5, 5) # Pequeno respiro nas bordas
        self.container_layout.setSpacing(0) # Cola os widgets verticalmente
        self.container_layout.setAlignment(Qt.AlignmentFlag.AlignTop) # Empilha tudo no topo

        self.label_top = QLabel('Arraste o arquivo .exe aqui', self)
        self.label_top.setStyleSheet(f"font-family: 'Consolas'; color: {label_color};")
        self.label_top.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.label_top.setWordWrap(True)
        self.label_top.setTextFormat(Qt.TextFormat.RichText)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search IAT or Strings...")
        self.search_bar.textChanged.connect(self.on_search_changed)
        self.search_bar.setVisible(False)

        self.label_bottom = QLabel('', self)
        self.label_bottom.setStyleSheet(f"font-family: 'Consolas'; color: {label_color};")
        self.label_bottom.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.label_bottom.setWordWrap(True)
        self.label_bottom.setTextFormat(Qt.TextFormat.RichText)

        self.container_layout.addWidget(self.label_top)
        self.container_layout.addWidget(self.search_bar)
        self.container_layout.addWidget(self.label_bottom)
        
        self.scroll.setWidget(self.container)
        layout.addWidget(self.scroll)

        self.info_str = ""
        self.entropy_str = ""
        self.iat_str = ""
        self.exports_str = ""
        self.strings_str = ""
        self.file_path = None
        self.all_strings = []
        self.all_iats = []
        self.all_exports = []

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
            if file_path.lower().endswith(('.exe', '.dll')):
                self.analyze(file_path)
            else:
                self.label.setText("Erro: Arraste apenas arquivos .exe")

    def get_section_entry_str(self, name:str) -> str:
        out = (
            f"<div style='text-align: center; width: 100%;'>"
            f"<span style='background-color: green; color: white; padding: 2px 10px;'>{name}</span>"
            f"</div>"
        )
        return out

    def extract_iat(self, pe:pefile.PE) -> str:
        results = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    address = hex(imp.address)
                    name = imp.name.decode() if imp.name else "Ordinal"
                    results.append({"l":entry.dll.decode(), "a":address, "n":name})
        return results

    def extract_exports(self, pe: pefile.PE):
        results = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode() if exp.name else f"Ordinal {exp.ordinal}"
                address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
                results.append({"n": name, "a": address})
        return results

    def on_search_changed(self):
        if self.file_path:
            with pefile.PE(self.file_path) as pe:
                self.update_iat(self.search_bar.text())
                self.update_exports(self.search_bar.text())
                self.update_strings(self.search_bar.text())
            self.update_label()

    def extract_strings(self, pe:pefile.PE, min_len:int=4) -> None:
        results = []
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

    def analyze(self, file_path:str) -> None:
        self.file_path = file_path
        self.info_str = ""
        self.entropy_str = ""
        self.iat_str = ""
        self.exports_str = ""
        self.strings_str = ""
        self.all_strings = []
        self.all_iats = []
        self.all_exports = []
        self.label_top.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.search_bar.setVisible(True)
        with pefile.PE(self.file_path) as pe:
            imphash = pe.get_imphash()
            md5 = hashlib.md5(pe.__data__).hexdigest()
            self.info_str = self.get_section_entry_str("INFO")
            creation_timestamp = read_pe_timestamp(self.file_path)
            creation_date = datetime.fromtimestamp(creation_timestamp).strftime('%d/%m/%Y %H:%M:%S')
            self.info_str += f"File: {os.path.basename(self.file_path)}<br>"
            self.info_str += f"Creation TimeStamp: {creation_timestamp} ({creation_date})<br>"
            self.info_str += f"MD5: {md5}<br>"
            self.info_str += f"ImpHash: {imphash}<br>"
            self.entropy_str = self.get_section_entry_str("ENTROPY")
            self.entropy_str += get_entropys(pe)
            self.all_iats = self.extract_iat(pe)
            self.all_exports = self.extract_exports(pe)
            self.all_strings = self.extract_strings(pe)
        self.on_search_changed()

    DANGEROUS_APIS = {
        # Process / Thread manipulation
        "CreateProcessA", "CreateProcessW",
        "NtCreateProcess", "NtCreateProcessEx",
        "CreateRemoteThread",
        "NtCreateThread", "NtCreateThreadEx",
        "ResumeThread", "SuspendThread",
        "GetThreadContext", "SetThreadContext",
        "Wow64GetThreadContext", "Wow64SetThreadContext",
        # Memory / Injection
        "VirtualAlloc", "VirtualAllocEx",
        "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtWriteVirtualMemory", "NtReadVirtualMemory",
        "MapViewOfFile", "UnmapViewOfFile",
        "NtMapViewOfSection", "NtUnmapViewOfSection",
        # DLL loading / resolving
        "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress",
        "LdrLoadDll", "LdrGetProcedureAddress",
        # Anti-debug / Anti-analysis
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "DebugActiveProcess", "DebugBreak",
        # Persistence / system
        "CreateServiceA", "CreateServiceW",
        "OpenSCManagerA", "OpenSCManagerW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "RegSetValueExA", "RegSetValueExW",
        # Network / C2
        "socket", "connect", "send", "recv", "WSAStartup",
        "InternetOpenA", "InternetOpenW", "InternetReadFile",
        "HttpSendRequestA", "HttpSendRequestW",
        "WinHttpSendRequest",
        # Crypto / packing
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
        "CryptCreateHash", "CryptHashData",
        "BCryptEncrypt", "BCryptDecrypt",
    }

    def update_iat(self, search:str=None) -> None:
        self.iat_str = self.get_section_entry_str("IAT")
        search = search.lower()
        filtered = [s for s in self.all_iats if not search or search in s['n'].lower()]
        self.iat_str += f"TOTAL IMPORTS: {len(self.all_iats)}<br>"
        total_flags = 0
        printed_dlls = []
        for elem in filtered:
            if elem["l"] not in printed_dlls:
                self.iat_str += f"DLL: {elem["l"]}<br>"
                printed_dlls.append(elem["l"])
            line = f"{elem['a']} = '{elem['n']}'"
            line = ("&nbsp;" * 8) + line #tab
            if elem['n'] in self.DANGEROUS_APIS:
                line = f"<span style='color: red;'>{line}</span>"
                total_flags += 1
            self.iat_str += f"{line}<br>"
        self.iat_str += f"TOTAL FLAGS: {total_flags}"

    def update_exports(self, search:str=None) -> None:
        self.exports_str = self.get_section_entry_str("EXPORTS")
        search = search.lower()
        filtered = [s for s in self.all_exports if not search or search in s['n'].lower()]
        self.exports_str += f"TOTAL EXPORTS: {len(self.all_exports)}<br>"
        for elem in filtered:
            line = f"name: {elem["n"]}, address: {elem["a"]}"
            self.exports_str += line

    def update_strings(self, search:str=None) -> None:
        self.strings_str = self.get_section_entry_str("STRINGS")
        search = search.lower()
        filtered = [s for s in self.all_strings if not search or search in s['s'].lower()]
        self.strings_str += f"TOTAL STRINGS = {len(filtered)}<br>"
        for elem in filtered:
            self.strings_str += f"{elem['f']} = '{elem['s']}'<br>"

    def update_label(self) -> None:
        self.label_top.setText(self.info_str + self.entropy_str)
        self.label_bottom.setText(self.iat_str + self.exports_str + self.strings_str)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = ExeAnalyzer()
    ex.show()
    if "main.py" in sys.argv[0]:
        print("debugging")
        import json
        with open("config.json", "r") as f:
            options = json.load(f)
            ex.analyze(options["debug_path"])
    if len(sys.argv) > 1:
        file_to_open = sys.argv[1]
        if os.path.exists(file_to_open) and file_to_open.lower().endswith(('.exe', '.lnk', '.dll')):
            if file_to_open.lower().endswith('.lnk'):
                file_to_open = get_shortcut_target(file_to_open)
            ex.analyze(file_to_open)
    sys.exit(app.exec())