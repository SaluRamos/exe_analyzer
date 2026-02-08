#libs
import winreg
import win32com.client
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QScrollArea, QLineEdit, QCheckBox, QTabWidget, QPushButton
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
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
import html
import time

CLANG_CRT_APIS = [ "GetCurrentProcessId", "GetCurrentThreadId", "RaiseException", "RtlPcToFileHeader", "WriteFile", "GetCurrentProcess", "GetModuleHandleExW", "FindFirstFileExW", "FindNextFileW", "GetEnvironmentStringsW", "SetEnvironmentVariableW", "VirtualProtect", "QueryPerformanceCounter", "GetSystemTimeAsFileTime", "InitializeSListHead", "SetUnhandledExceptionFilter", "GetStartupInfoW", "GetModuleHandleW", "WriteConsoleW", "RtlUnwindEx", "GetLastError", "SetLastError", "FlsAlloc", "FlsGetValue", "FlsSetValue", "FlsFree", "EnterCriticalSection", "LeaveCriticalSection", "InitializeCriticalSectionEx", "DeleteCriticalSection", "RtlLookupFunctionEntry", "EncodePointer", "GetStdHandle", "GetModuleFileNameW", "ExitProcess", "TerminateProcess", "FreeLibrary", "GetProcAddress", "GetCommandLineA", "GetCommandLineW", "IsProcessorFeaturePresent", "RtlCaptureContext", "RtlVirtualUnwind", "IsDebuggerPresent", "UnhandledExceptionFilter", "HeapAlloc", "HeapFree", "FindClose", "IsValidCodePage", "GetACP", "GetOEMCP", "GetCPInfo", "MultiByteToWideChar", "WideCharToMultiByte", "FreeEnvironmentStringsW", "SetStdHandle", "GetFileType", "GetStringTypeW", "LoadLibraryExW", "CompareStringW", "LCMapStringW", "GetProcessHeap", "HeapSize", "HeapReAlloc", "FlushFileBuffers", "GetConsoleOutputCP", "GetConsoleMode", "SetFilePointerEx", "CreateFileW", "CloseHandle" ]

DANGEROUS_APIS = [ "CreateProcessA", "CreateProcessW", "NtCreateProcess", "NtCreateProcessEx", "CreateRemoteThread", "NtCreateThread", "NtCreateThreadEx", "ResumeThread", "SuspendThread", "GetThreadContext", "SetThreadContext", "Wow64GetThreadContext", "Wow64SetThreadContext", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory", "MapViewOfFile", "UnmapViewOfFile", "NtMapViewOfSection", "NtUnmapViewOfSection", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread", "OutputDebugString", "DebugActiveProcess", "DebugBreak", "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW", "socket", "connect", "send", "recv", "WSAStartup", "InternetOpenA", "InternetOpenW", "InternetReadFile", "HttpSendRequestA", "HttpSendRequestW", "WinHttpSendRequest", "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData", "BCryptEncrypt", "BCryptDecrypt", "GetCurrentProcessId", "GetCurrentThreadId", "QueryPerformanceFrequency", "FindFirstFileW", "FindFirstFileExW", "FindNextFileW", "GetFileInformationByHandleEx", "RaiseException", "GetCurrentProcess", "GetModuleHandleExW", "WriteFile", "GetEnvironmentStringsW", "SetEnvironmentVariableW", "ShellExecuteExW", "RtlPcToFileHeader" ]

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

#--------------------------------------------CLASSES--------------------------------------------

class MyHandler(FileSystemEventHandler):

    def __init__(self, app: ExeAnalyzer):
        self.app = app
        super().__init__()

    def on_modified(self, event) -> None:
        if not event.is_directory:
            if os.path.abspath(event.src_path) == os.path.abspath(self.app.file_path):
                print(f"O arquivo {event.src_path} foi modificado!")
                self.app.update_signal.emit(self.app.file_path)

class ExeAnalyzer(QWidget):

    update_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.initUI()
        self.update_signal.connect(self.run_analysis_safe)
        
    def initUI(self) -> None:
        self.setWindowTitle('Exe analyzer by Salu C Ramos')
        self.setFixedSize(460, 700)
        # self.resize(440, 700)
        # self.setMinimumWidth(460) 
        # self.setMinimumHeight(500)
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

        self.file_path = None #pré declaração

        self.btn_update = QPushButton("Update", self)
        self.btn_update.setFixedWidth(100)
        self.btn_update.clicked.connect(lambda: self.run_analysis_safe(self.file_path))

        self.label_top = QLabel('Arraste o arquivo .exe aqui', self)
        self.label_top.setStyleSheet(f"font-family: 'Consolas'; color: {label_color};")
        self.label_top.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.label_top.setWordWrap(True)
        self.label_top.setTextFormat(Qt.TextFormat.RichText)

        self.string_filter_checkbox = QCheckBox("use valid string filter")
        self.string_filter_checkbox.setStyleSheet(f"color: {label_color}; font-family: 'Consolas';")
        self.string_filter_checkbox.setVisible(False)
        self.string_filter_checkbox.stateChanged.connect(self.on_search_changed)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search IAT or Strings...")
        self.search_bar.textChanged.connect(self.on_search_changed)
        self.search_bar.setVisible(False)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"color: {label_color}; font-family: 'Consolas';")
        self.tabs.currentChanged.connect(self.on_search_changed)
        self.label_imports = QLabel("")
        self.label_exports = QLabel("")
        self.label_strings = QLabel("")
        for label in [self.label_imports, self.label_exports, self.label_strings]:
            label.setStyleSheet(f"font-family: 'Consolas'; color: {label_color};")
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            label.setWordWrap(True)
            label.setTextFormat(Qt.TextFormat.RichText)
            label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.tabs.addTab(self.label_imports, "Imports")
        self.tabs.addTab(self.label_exports, "Exports")
        self.tabs.addTab(self.label_strings, "Strings")

        self.container_layout.addWidget(self.btn_update, alignment=Qt.AlignmentFlag.AlignCenter)
        self.container_layout.addWidget(self.label_top)
        self.container_layout.addWidget(self.string_filter_checkbox)
        self.container_layout.addWidget(self.search_bar)
        self.container_layout.addWidget(self.tabs)
        
        self.scroll.setWidget(self.container)
        layout.addWidget(self.scroll)

        self.info_str = []
        self.entropy_str = []
        self.iat_str = []
        self.exports_str = []
        self.strings_str = []
        self.filtered_strings = []
        self.all_strings = []
        self.all_iats = []
        self.all_exports = []
        self.observer = None

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
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

    def on_search_changed(self) -> None:
        if self.file_path:
            title = self.tabs.tabText(self.tabs.currentIndex())
            # print(title)
            if title == "Imports":
                self.update_iat(self.search_bar.text())
                iat_final = "".join(self.iat_str)
                self.label_imports.setText(iat_final)
            elif title == "Exports":
                self.update_exports(self.search_bar.text())
                exports_final = "".join(self.exports_str)
                self.label_exports.setText(exports_final)
            else:
                self.update_strings(self.search_bar.text())
                strings_final = "".join(self.strings_str)
                self.label_strings.setText(strings_final)

    def extract_strings(self, pe: pefile.PE, use_filter: bool, min_len: int = 4) -> list:
        results = []
        for section in pe.sections:
            try:
                section_name = section.Name.strip(b'\x00').decode("utf-8", errors='ignore')
            except:
                section_name = "unknown"
            data = section.get_data()
            # ASCII
            for m in PRINTABLE_RE.finditer(data):
                try:
                    s = m.group().decode("ascii")
                    if len(s) >= min_len:
                        if not use_filter or is_valid_string(s):
                            results.append({"f": section_name, "s": s})
                except UnicodeDecodeError:
                    continue
            # UTF-16LE
            for m in UTF16_RE.finditer(data):
                try:
                    s = m.group().decode("utf-16le")
                    if len(s) >= min_len:
                        if not use_filter or is_valid_string(s):
                            results.append({"f": section_name, "s": s})
                except UnicodeDecodeError:
                    continue
        return results

    def analyze(self, file_path: str) -> None:
        """Configura o monitoramento e roda a primeira análise"""
        if file_path is None:
            return
        self.file_path = os.path.abspath(file_path)
        # Configura o observer apenas se for um arquivo novo
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.observer = Observer()
        directory = os.path.dirname(self.file_path)
        self.observer.schedule(MyHandler(self), directory, recursive=False)
        print(f"Monitorando: {self.file_path}")
        self.observer.start()
        self.run_analysis_safe(self.file_path)

    def run_analysis_safe(self, file_path: str):
        """Método que roda na Thread Principal e atualiza a GUI"""
        print(f"analyzing: {file_path}")
        self.file_path = file_path
        self.info_str = []
        self.entropy_str = []
        self.iat_str = []
        self.exports_str = []
        self.strings_str = []
        self.filtered_strings = []
        self.all_strings = []
        self.all_iats = []
        self.all_exports = []
        self.label_top.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.search_bar.setVisible(True)
        self.string_filter_checkbox.setVisible(True)

        pe = None
        max_retries = 20
        for attempt in range(max_retries):
            try:
                pe = pefile.PE(file_path)
                break
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"attempt {attempt}")
                    time.sleep(0.5)
                else:
                    print("Erro: O arquivo permaneceu bloqueado por muito tempo.")
                    return
                
        imphash = pe.get_imphash()
        md5 = hashlib.md5(pe.__data__).hexdigest()
        self.info_str.append(self.get_section_entry_str("INFO"))
        creation_timestamp = read_pe_timestamp(self.file_path)
        creation_date = datetime.fromtimestamp(creation_timestamp).strftime('%d/%m/%Y %H:%M:%S')
        self.info_str.append(f"File: {os.path.basename(self.file_path)}<br>")
        self.info_str.append(f"Creation TimeStamp: {creation_timestamp} ({creation_date})<br>")
        self.info_str.append(f"MD5: {md5}<br>")
        self.info_str.append(f"ImpHash: {imphash}")
        self.entropy_str.append(self.get_section_entry_str("ENTROPY"))
        self.entropy_str.append(get_entropys(pe))
        self.all_iats = self.extract_iat(pe)
        self.all_exports = self.extract_exports(pe)
        self.filtered_strings = self.extract_strings(pe, True)
        self.all_strings = self.extract_strings(pe, False)

        pe.close()

        info_final = "".join(self.info_str)
        entropys_final = "".join(self.entropy_str)
        self.label_top.setText(info_final + entropys_final)

        self.on_search_changed()

    def update_iat(self, search:str=None) -> None:
        self.iat_str = []
        search = search.lower()
        filtered = [s for s in self.all_iats if not search or search in s['n'].lower()]
        self.iat_str.append(f"TOTAL IMPORTS: {len(self.all_iats)}")
        total_flags = 0
        printed_dlls = []
        if len(filtered) > 0:
            self.iat_str.append("<br>")
        for elem in filtered:
            if elem["l"] not in printed_dlls:
                self.iat_str.append(f"DLL: {elem["l"]}<br>")
                printed_dlls.append(elem["l"])
            line = f"{elem['a']} = '{elem['n']}'"
            line = ("&nbsp;" * 8) + line #tab
            if elem['n'] in DANGEROUS_APIS:
                if elem['n'] in CLANG_CRT_APIS:
                    line = f"<span style='color: yellow;'>{line}</span>"
                else:
                    line = f"<span style='color: red;'>{line}</span>"
                total_flags += 1
            self.iat_str.append(f"{line}<br>")
        self.iat_str.append(f"TOTAL FLAGS: {total_flags}")

    def update_exports(self, search:str=None) -> None:
        self.exports_str = []
        search = search.lower()
        filtered = [s for s in self.all_exports if not search or search in s['n'].lower()]
        self.exports_str.append(f"TOTAL EXPORTS: {len(self.all_exports)}")
        if len(filtered) > 0:
            self.exports_str.append("<br>")
        for elem in filtered:
            line = f"name: {elem["n"]}, address: {elem["a"]}"
            self.exports_str.append(f"{line}<br>")
        self.exports_str[-1][:-4] #remove o ultimo <br>

    def update_strings(self, search:str=None) -> None:
        self.strings_str = []
        search = search.lower()
        if self.string_filter_checkbox.isChecked():
            filtered = [s for s in self.filtered_strings if not search or search in s['s'].lower()]
        else:
            filtered = [s for s in self.all_strings if not search or search in s['s'].lower()]
        self.strings_str.append(f"TOTAL STRINGS = {len(filtered)}")
        if len(filtered) > 0:
            self.strings_str.append("<br>")
        for elem in filtered:
            line = f"{elem['f']} = '{elem['s']}'"
            safe_data = html.escape(str(line))
            self.strings_str.append(f"{safe_data}<br>")
        self.strings_str[-1][:-4] #remove o ultimo <br>
        
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