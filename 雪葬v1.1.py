import sys
import ctypes
import warnings
import time
import winreg
import win32api
import win32security
import win32con
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QHeaderView, 
    QPushButton, QVBoxLayout, QWidget, QLabel, QSplitter, QHBoxLayout, 
    QMessageBox, QMenu, QAction, QLineEdit, QCheckBox, QProgressBar,
    QStyleFactory, QSystemTrayIcon, QDialog, QGridLayout, QComboBox
)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QMovie
from win32con import PROCESS_ALL_ACCESS, THREAD_SUSPEND_RESUME, PROCESS_TERMINATE
from win32api import OpenProcess, CloseHandle

# 过滤SIP警告
warnings.filterwarnings("ignore", category=DeprecationWarning, message="sipPyTypeDict.*")

# 定义 Windows API 结构体和函数
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t)
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260)
    ]

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

# API 函数声明
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32First = kernel32.Process32First
Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32First.restype = wintypes.BOOL

Process32Next = kernel32.Process32Next
Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32Next.restype = wintypes.BOOL

Thread32First = kernel32.Thread32First
Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
Thread32First.restype = wintypes.BOOL

Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
Thread32Next.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetProcessMemoryInfo = psapi.GetProcessMemoryInfo
GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
GetProcessMemoryInfo.restype = wintypes.BOOL

GetProcessTimes = kernel32.GetProcessTimes
GetProcessTimes.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME)
]
GetProcessTimes.restype = wintypes.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t
]
VirtualQueryEx.restype = ctypes.c_size_t

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
VirtualProtectEx.restype = wintypes.BOOL

TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
TerminateProcess.restype = wintypes.BOOL

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04

class ProcessFilterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("进程过滤设置")
        self.setGeometry(400, 400, 400, 300)
        self.init_ui()
        
    def init_ui(self):
        layout = QGridLayout()
        
        # 系统进程过滤
        layout.addWidget(QLabel("系统进程:"), 0, 0)
        self.system_proc_combo = QComboBox()
        self.system_proc_combo.addItems(["显示所有", "仅显示用户进程", "隐藏关键系统进程"])
        layout.addWidget(self.system_proc_combo, 0, 1)
        
        # 内存占用过滤
        layout.addWidget(QLabel("最小内存(MB):"), 1, 0)
        self.memory_min_spin = QLineEdit("10")
        self.memory_min_spin.setMaximumWidth(80)
        layout.addWidget(self.memory_min_spin, 1, 1)
        
        # CPU占用过滤
        layout.addWidget(QLabel("最小CPU(%):"), 2, 0)
        self.cpu_min_spin = QLineEdit("0.1")
        self.cpu_min_spin.setMaximumWidth(80)
        layout.addWidget(self.cpu_min_spin, 2, 1)
        
        # 冻结状态过滤
        layout.addWidget(QLabel("冻结状态:"), 3, 0)
        self.frozen_filter_combo = QComboBox()
        self.frozen_filter_combo.addItems(["全部", "仅冻结", "仅运行"])
        layout.addWidget(self.frozen_filter_combo, 3, 1)
        
        # 按钮
        self.apply_btn = QPushButton("应用")
        self.apply_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.reject)
        
        layout.addWidget(self.apply_btn, 4, 0)
        layout.addWidget(self.cancel_btn, 4, 1)
        
        self.setLayout(layout)

class SnowBurial(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("雪葬 - 进程冻结工具 v1.1")
        self.setGeometry(300, 300, 1200, 800)
        
        # 设置应用样式
        QApplication.setStyle(QStyleFactory.create('Fusion'))
        
        # 深色主题
        self.set_dark_theme()
        
        # 初始化UI
        self.init_ui()
        
        # 获取管理员权限
        self.enable_debug_privilege()
        
        # 存储进程冻结状态
        self.frozen_processes = {}
        self.memory_protected = {}  # 存储内存保护状态及原始保护属性
        self.old_protections = {}   # 保存原始内存保护属性

        # 存储CPU使用率信息
        self.last_cpu_times = {}
        self.last_update_time = time.time()

        # 初始化过滤设置
        self.filter_settings = {
            'min_memory': 10.0,
            'min_cpu': 0.1,
            'system_proc': 0,  # 0=显示所有, 1=仅用户进程, 2=隐藏关键
            'frozen_filter': 0  # 0=全部, 1=仅冻结, 2=仅运行
        }

        # 刷新进程列表
        self.refresh_process_list()

        # 设置定时刷新
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_process_list)
        self.timer.start(2500)

        # 创建系统托盘图标
        self.create_system_tray()
        
        # 创建动画（如果没有snow.gif，会显示空白但不报错）
        self.snow_animation = QMovie("snow.gif")
        self.animation_label = QLabel()
        self.animation_label.setMovie(self.snow_animation)
        self.snow_animation.start()
        self.statusBar().addPermanentWidget(self.animation_label)
        
    def set_dark_theme(self):
        """应用深色主题"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(dark_palette)
        
    def create_system_tray(self):
        """创建系统托盘图标"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("snow_icon.ico") if QIcon("snow_icon.ico").isNull() else QIcon())
        
        tray_menu = QMenu()
        show_action = tray_menu.addAction("显示窗口")
        show_action.triggered.connect(self.show)
        
        freeze_action = tray_menu.addAction("冻结高资源进程")
        freeze_action.triggered.connect(self.auto_freeze_high_resource)
        
        tray_menu.addSeparator()
        exit_action = tray_menu.addAction("退出")
        exit_action.triggered.connect(sys.exit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_activated)
        
    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            
    def init_ui(self):
        # 创建主布局
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # 创建顶部控制面板
        control_layout = QHBoxLayout()
        
        # 添加搜索框
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("搜索进程...")
        self.search_box.textChanged.connect(self.filter_process_list)
        control_layout.addWidget(QLabel("搜索:"))
        control_layout.addWidget(self.search_box)
        
        # 添加自动冻结选项
        self.auto_freeze_check = QCheckBox("自动冻结高CPU进程")
        self.auto_freeze_check.stateChanged.connect(self.toggle_auto_freeze)
        control_layout.addWidget(self.auto_freeze_check)
        
        # 添加过滤按钮
        self.filter_btn = QPushButton("过滤设置")
        self.filter_btn.clicked.connect(self.show_filter_dialog)
        control_layout.addWidget(self.filter_btn)
        
        # 添加刷新按钮
        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.setIcon(QIcon("refresh.ico") if QIcon("refresh.ico").isNull() else QIcon())
        self.refresh_btn.setIconSize(QSize(16, 16))
        self.refresh_btn.clicked.connect(self.refresh_process_list)
        
        # 添加冻结按钮
        self.freeze_btn = QPushButton("冻结选中")
        self.freeze_btn.setIcon(QIcon("freeze.ico") if QIcon("freeze.ico").isNull() else QIcon())
        self.freeze_btn.setIconSize(QSize(16, 16))
        self.freeze_btn.clicked.connect(self.freeze_selected)
        
        # 添加解冻按钮
        self.unfreeze_btn = QPushButton("解冻选中")
        self.unfreeze_btn.setIcon(QIcon("unfreeze.ico") if QIcon("unfreeze.ico").isNull() else QIcon())
        self.unfreeze_btn.setIconSize(QSize(16, 16))
        self.unfreeze_btn.clicked.connect(self.unfreeze_selected)
        
        # 添加内存保护按钮
        self.protect_btn = QPushButton("内存保护")
        self.protect_btn.setIcon(QIcon("protect.ico") if QIcon("protect.ico").isNull() else QIcon())
        self.protect_btn.setIconSize(QSize(16, 16))
        self.protect_btn.clicked.connect(self.protect_memory)
        
        # 添加解除保护按钮
        self.unprotect_btn = QPushButton("解除保护")
        self.unprotect_btn.setIcon(QIcon("unprotect.ico") if QIcon("unprotect.ico").isNull() else QIcon())
        self.unprotect_btn.setIconSize(QSize(16, 16))
        self.unprotect_btn.clicked.connect(self.unprotect_memory)
        
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.freeze_btn)
        control_layout.addWidget(self.unfreeze_btn)
        control_layout.addWidget(self.protect_btn)
        control_layout.addWidget(self.unprotect_btn)
        
        # 添加统计面板
        stats_layout = QHBoxLayout()
        
        self.total_proc_label = QLabel("进程总数: 0")
        self.total_proc_label.setStyleSheet("font-weight: bold; color: #4FC3F7;")
        
        self.frozen_proc_label = QLabel("冻结进程: 0")
        self.frozen_proc_label.setStyleSheet("font-weight: bold; color: #F44336;")
        
        self.mem_usage_label = QLabel("内存使用: 0 MB")
        self.mem_usage_label.setStyleSheet("font-weight: bold; color: #81C784;")
        
        self.cpu_usage_label = QLabel("CPU使用: 0%")
        self.cpu_usage_label.setStyleSheet("font-weight: bold; color: #FFB74D;")
        
        stats_layout.addWidget(self.total_proc_label)
        stats_layout.addWidget(self.frozen_proc_label)
        stats_layout.addWidget(self.mem_usage_label)
        stats_layout.addWidget(self.cpu_usage_label)
        stats_layout.addStretch()
        
        # 创建进程列表
        self.process_tree = QTreeWidget()
        self.process_tree.setColumnCount(7)
        self.process_tree.setHeaderLabels(["PID", "进程名", "状态", "CPU(%)", "内存(MB)", "线程数", "描述"])
        self.process_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.process_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.process_tree.setSortingEnabled(True)
        self.process_tree.sortByColumn(0, Qt.AscendingOrder)
        self.process_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #2D2D30;
                color: #E0E0E0;
                alternate-background-color: #3E3E42;
            }
            QHeaderView::section {
                background-color: #252526;
                color: #D0D0D0;
                padding: 4px;
                border: 1px solid #1B1B1C;
            }
        """)
        self.process_tree.setAlternatingRowColors(True)
        self.process_tree.header().setSectionResizeMode(QHeaderView.Interactive)
        
        # 添加资源使用监控
        self.cpu_monitor = QProgressBar()
        self.cpu_monitor.setRange(0, 100)
        self.cpu_monitor.setFormat("系统CPU使用率: %p%")
        self.cpu_monitor.setStyleSheet("""
            QProgressBar {
                border: 2px solid #424242;
                border-radius: 5px;
                text-align: center;
                background: #2E2E2E;
            }
            QProgressBar::chunk {
                background-color: #FF5722;
                width: 10px;
            }
        """)
        
        self.mem_monitor = QProgressBar()
        self.mem_monitor.setRange(0, 100)
        self.mem_monitor.setFormat("系统内存使用率: %p%")
        self.mem_monitor.setStyleSheet("""
            QProgressBar {
                border: 2px solid #424242;
                border-radius: 5px;
                text-align: center;
                background: #2E2E2E;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                width: 10px;
            }
        """)
        
        # 创建状态栏
        self.status_label = QLabel("就绪 | 系统: Windows")
        self.statusBar().addPermanentWidget(self.status_label)
        
        # 添加到主布局
        main_layout.addLayout(control_layout)
        main_layout.addLayout(stats_layout)
        main_layout.addWidget(self.process_tree)
        main_layout.addWidget(self.cpu_monitor)
        main_layout.addWidget(self.mem_monitor)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 设置窗口图标
        self.setWindowIcon(QIcon("snow_icon.ico") if QIcon("snow_icon.ico").isNull() else QIcon())
        
    def enable_debug_privilege(self):
        """启用调试权限以操作其他进程"""
        try:
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            privilege_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
            win32security.AdjustTokenPrivileges(
                hToken, 
                False, 
                [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
            )
            win32api.CloseHandle(hToken)
        except Exception as e:
            self.status_label.setText(f"警告: 无法获取调试权限 - {str(e)}")
    
    def get_process_description(self, pid):
        """获取进程描述信息"""
        try:
            # 使用更可靠的方法获取进程描述
            hProcess = OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
            if not hProcess:
                return ""
                
            try:
                # 获取进程可执行文件路径
                exe_path = ctypes.create_unicode_buffer(260)
                size = ctypes.c_uint(260)
                if ctypes.windll.psapi.GetModuleFileNameExW(hProcess, None, exe_path, size) == 0:
                    return ""
                
                # 获取文件版本信息
                info_size = ctypes.windll.version.GetFileVersionInfoSizeW(exe_path.value, None)
                if info_size == 0:
                    return ""
                
                info = ctypes.create_string_buffer(info_size)
                if ctypes.windll.version.GetFileVersionInfoW(exe_path.value, 0, info_size, info) == 0:
                    return ""
                
                # 获取描述信息
                value = ctypes.c_void_p()
                value_len = ctypes.c_uint()
                if ctypes.windll.version.VerQueryValueW(info, "\\StringFileInfo\\040904b0\\FileDescription", 
                                                       ctypes.byref(value), ctypes.byref(value_len)) == 0:
                    return ""
                
                # 读取描述字符串
                description = ctypes.c_wchar_p(value.value).value
                return description if description else ""
            finally:
                CloseHandle(hProcess)
        except:
            return ""
    
    def get_process_list(self):
        """使用Windows API获取进程列表"""
        processes = []
        total_memory = 0
        total_cpu = 0
        critical_pids = [0, 4]  # 系统关键进程ID
        
        # 创建进程快照
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if hSnapshot == -1:
            error = ctypes.GetLastError()
            self.status_label.setText(f"错误: 无法创建进程快照 (错误代码: {error})")
            return processes
        
        try:
            # 初始化PROCESSENTRY32结构
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            # 获取第一个进程
            if not Process32First(hSnapshot, ctypes.byref(pe32)):
                error = ctypes.GetLastError()
                self.status_label.setText(f"错误: 无法获取第一个进程 (错误代码: {error})")
                return processes
            
            # 遍历进程
            while True:
                pid = pe32.th32ProcessID
                try:
                    # 处理可能存在的编码问题
                    name_bytes = bytes(pe32.szExeFile)
                    if b'\x00' in name_bytes:
                        name = name_bytes[:name_bytes.index(b'\x00')].decode('latin1', errors='replace')
                    else:
                        name = name_bytes.decode('latin1', errors='replace')
                except Exception as e:
                    name = "Unknown"
                
                threads = pe32.cntThreads
                
                # 跳过关键系统进程
                if self.filter_settings['system_proc'] == 2 and pid in critical_pids:
                    if not Process32Next(hSnapshot, ctypes.byref(pe32)):
                        break
                    continue
                
                # 获取进程描述
                description = self.get_process_description(pid)
                
                # 获取进程内存信息
                memory_usage = 0
                try:
                    hProcess = OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
                    if hProcess:
                        try:
                            pmc = PROCESS_MEMORY_COUNTERS_EX()
                            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
                            if GetProcessMemoryInfo(hProcess, ctypes.byref(pmc), ctypes.sizeof(pmc)):
                                memory_usage = pmc.PrivateUsage  # 使用私有工作集大小
                        finally:
                            CloseHandle(hProcess)
                except:
                    pass
                
                # 计算CPU使用率
                cpu_percent = 0.0
                current_time = time.time()
                if pid in self.last_cpu_times:
                    last_time, last_cpu = self.last_cpu_times[pid]
                    time_diff = current_time - last_time
                    if time_diff > 0:
                        cpu_percent = (self.get_cpu_time(pid) - last_cpu) / time_diff * 100
                
                # 保存当前CPU时间
                cpu_time = self.get_cpu_time(pid)
                self.last_cpu_times[pid] = (current_time, cpu_time)
                
                # 更新总统计
                total_memory += memory_usage
                total_cpu += cpu_percent
                
                processes.append({
                    'pid': pid,
                    'name': name,
                    'memory': memory_usage / (1024 * 1024),  # 转换为MB
                    'cpu': cpu_percent,
                    'threads': threads,
                    'description': description
                })
                
                # 获取下一个进程
                if not Process32Next(hSnapshot, ctypes.byref(pe32)):
                    break
        except Exception as e:
            self.status_label.setText(f"进程枚举错误: {str(e)}")
        finally:
            # 确保快照句柄被关闭
            CloseHandle(hSnapshot)
        
        # 更新系统资源监控
        self.update_system_resources(total_memory, total_cpu, len(processes))
        
        return processes
    
    def update_system_resources(self, total_memory, total_cpu, process_count):
        """更新系统资源监控显示"""
        # 获取系统内存信息
        mem_info = self.get_system_memory_info()
        
        if mem_info:
            mem_percent = (mem_info['total'] - mem_info['free']) / mem_info['total'] * 100
            self.mem_usage_label.setText(f"内存使用: {total_memory/1024/1024:.2f} GB / 总内存: {mem_info['total']/1024/1024:.2f} GB")
            self.mem_monitor.setValue(int(mem_percent))
        
        # 更新CPU监控（限制在0-100范围内）
        cpu_usage = min(100, max(0, total_cpu))
        self.cpu_monitor.setValue(int(cpu_usage))
        
        # 更新进程统计
        frozen_count = len(self.frozen_processes)
        self.total_proc_label.setText(f"进程总数: {process_count}")
        self.frozen_proc_label.setText(f"冻结进程: {frozen_count}")
        self.cpu_usage_label.setText(f"总CPU使用: {cpu_usage:.2f}%")
    
    def get_system_memory_info(self):
        """获取系统内存信息"""
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)
            ]
            
            def __init__(self):
                self.dwLength = ctypes.sizeof(self)
                super().__init__()
        
        mem_status = MEMORYSTATUSEX()
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
            return {
                'total': mem_status.ullTotalPhys,
                'free': mem_status.ullAvailPhys,
                'percent_used': mem_status.dwMemoryLoad
            }
        return None
    
    def get_cpu_time(self, pid):
        """获取进程的CPU时间（秒）"""
        try:
            hProcess = OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            if not hProcess:
                return 0.0
                
            try:
                creation_time = wintypes.FILETIME()
                exit_time = wintypes.FILETIME()
                kernel_time = wintypes.FILETIME()
                user_time = wintypes.FILETIME()
                
                if GetProcessTimes(hProcess, ctypes.byref(creation_time), ctypes.byref(exit_time),
                                ctypes.byref(kernel_time), ctypes.byref(user_time)):
                    # 将FILETIME转换为64位整数
                    kernel = (kernel_time.dwHighDateTime << 32) + kernel_time.dwLowDateTime
                    user = (user_time.dwHighDateTime << 32) + user_time.dwLowDateTime
                    total_time = (kernel + user) / 10000000.0  # 转换为秒
                    return total_time
            finally:
                CloseHandle(hProcess)
        except:
            pass
        return 0.0
    
    def get_process_threads(self, pid):
        """获取指定进程的所有线程ID"""
        thread_ids = []
        
        # 创建线程快照
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if hSnapshot == -1:
            return thread_ids
        
        try:
            # 初始化THREADENTRY32结构
            te32 = THREADENTRY32()
            te32.dwSize = ctypes.sizeof(THREADENTRY32)
            
            # 获取第一个线程
            if not Thread32First(hSnapshot, ctypes.byref(te32)):
                return thread_ids
            
            # 遍历线程
            while True:
                if te32.th32OwnerProcessID == pid:
                    thread_ids.append(te32.th32ThreadID)
                    
                # 获取下一个线程
                if not Thread32Next(hSnapshot, ctypes.byref(te32)):
                    break
        finally:
            CloseHandle(hSnapshot)
        
        return thread_ids
    
    def refresh_process_list(self):
        """刷新进程列表"""
        self.process_tree.clear()
        
        processes = self.get_process_list()
        search_text = self.search_box.text().lower()
        
        total_count = 0
        frozen_count = 0
        total_memory = 0
        total_cpu = 0
        
        for proc in processes:
            pid = proc['pid']
            name = proc['name']
            status = "冻结" if pid in self.frozen_processes else "运行"
            cpu = proc['cpu']
            memory = proc['memory']
            threads = proc['threads']
            description = proc['description']
            
            # 应用过滤设置
            if self.filter_settings['min_memory'] > 0 and memory < self.filter_settings['min_memory']:
                continue
                
            if self.filter_settings['min_cpu'] > 0 and cpu < self.filter_settings['min_cpu']:
                continue
                
            if self.filter_settings['frozen_filter'] == 1 and status != "冻结":
                continue
                
            if self.filter_settings['frozen_filter'] == 2 and status == "冻结":
                continue
                
            # 应用搜索过滤
            if search_text and search_text not in name.lower() and search_text not in description.lower():
                continue
            
            item = QTreeWidgetItem(self.process_tree)
            item.setText(0, str(pid))
            item.setText(1, name)
            item.setText(2, status)
            item.setText(3, f"{cpu:.1f}")
            item.setText(4, f"{memory:.2f}")
            item.setText(5, str(threads))
            item.setText(6, description)
            
            # 标记冻结进程
            if status == "冻结":
                for i in range(7):
                    item.setBackground(i, QColor(70, 70, 70))
                    item.setForeground(i, QColor(220, 220, 220))
                frozen_count += 1
            
            total_count += 1
            total_memory += memory
            total_cpu += cpu
        
        # 调整列宽
        for i in range(7):
            self.process_tree.resizeColumnToContents(i)
        
        # 更新状态栏
        self.status_label.setText(f"就绪 | 进程: {total_count} | 冻结: {frozen_count} | 内存: {total_memory:.2f} MB | CPU: {total_cpu:.2f}%")
        
        # 检查自动冻结规则
        if self.auto_freeze_check.isChecked():
            self.auto_freeze_high_resource()
    
    def auto_freeze_high_resource(self):
        """自动冻结高资源消耗进程"""
        high_cpu_threshold = 30.0  # CPU使用率超过30%
        high_memory_threshold = 500.0  # 内存使用超过500MB
        
        processes = self.get_process_list()
        for proc in processes:
            pid = proc['pid']
            name = proc['name']
            cpu = proc['cpu']
            memory = proc['memory']
            
            # 跳过已冻结进程和系统关键进程
            if pid in self.frozen_processes or pid in [0, 4]:
                continue
                
            # 检查是否满足冻结条件
            if cpu > high_cpu_threshold or memory > high_memory_threshold:
                self.freeze_process(pid)
                self.status_label.setText(f"自动冻结: {name} (PID: {pid}) | CPU: {cpu:.1f}% | 内存: {memory:.2f} MB")
    
    def show_context_menu(self, position):
        """显示右键菜单"""
        item = self.process_tree.itemAt(position)
        if not item:
            return
        
        pid = int(item.text(0))
        name = item.text(1)
        status = item.text(2)
        
        menu = QMenu()
        
        if status == "冻结":
            unfreeze_action = QAction(f"解冻进程: {name}", self)
            unfreeze_action.triggered.connect(lambda: self.unfreeze_process(pid))
            menu.addAction(unfreeze_action)
            
            if pid in self.memory_protected:
                unprotect_action = QAction("解除内存保护", self)
                unprotect_action.triggered.connect(lambda: self.unprotect_memory(pid))
                menu.addAction(unprotect_action)
            else:
                protect_action = QAction("启用内存保护", self)
                protect_action.triggered.connect(lambda: self.protect_memory(pid))
                menu.addAction(protect_action)
        else:
            freeze_action = QAction(f"冻结进程: {name}", self)
            freeze_action.triggered.connect(lambda: self.freeze_process(pid))
            menu.addAction(freeze_action)
        
        # 添加结束进程选项
        kill_action = QAction(f"结束进程: {name}", self)
        kill_action.triggered.connect(lambda: self.kill_process(pid))
        menu.addAction(kill_action)
        
        menu.exec_(self.process_tree.viewport().mapToGlobal(position))
    
    def filter_process_list(self):
        """根据搜索框内容过滤进程列表"""
        self.refresh_process_list()
    
    def show_filter_dialog(self):
        """显示过滤设置对话框"""
        dialog = ProcessFilterDialog(self)
        dialog.system_proc_combo.setCurrentIndex(self.filter_settings['system_proc'])
        dialog.memory_min_spin.setText(str(self.filter_settings['min_memory']))
        dialog.cpu_min_spin.setText(str(self.filter_settings['min_cpu']))
        dialog.frozen_filter_combo.setCurrentIndex(self.filter_settings['frozen_filter'])
        
        if dialog.exec_() == QDialog.Accepted:
            try:
                self.filter_settings['system_proc'] = dialog.system_proc_combo.currentIndex()
                self.filter_settings['min_memory'] = float(dialog.memory_min_spin.text())
                self.filter_settings['min_cpu'] = float(dialog.cpu_min_spin.text())
                self.filter_settings['frozen_filter'] = dialog.frozen_filter_combo.currentIndex()
                self.refresh_process_list()
            except ValueError:
                QMessageBox.warning(self, "输入错误", "请输入有效的数字值")
    
    def toggle_auto_freeze(self, state):
        """切换自动冻结状态"""
        if state == Qt.Checked:
            self.status_label.setText("自动冻结已启用")
        else:
            self.status_label.setText("自动冻结已禁用")
    
    def freeze_selected(self):
        """冻结选中的进程"""
        selected_items = self.process_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择进程")
            return
        
        for item in selected_items:
            pid = int(item.text(0))
            if pid not in self.frozen_processes and pid not in [0, 4]:  # 不冻结关键系统进程
                self.freeze_process(pid)
    
    def unfreeze_selected(self):
        """解冻选中的进程"""
        selected_items = self.process_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择进程")
            return
        
        for item in selected_items:
            pid = int(item.text(0))
            if pid in self.frozen_processes:
                self.unfreeze_process(pid)
    
    def freeze_process(self, pid):
        """冻结指定进程"""
        try:
            # 挂起进程的所有线程
            self.suspend_process(pid)
            self.frozen_processes[pid] = True
            self.status_label.setText(f"已冻结进程: {pid}")
            self.refresh_process_list()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"冻结进程失败: {str(e)}")
    
    def unfreeze_process(self, pid):
        """解冻指定进程"""
        try:
            # 恢复进程的所有线程
            self.resume_process(pid)
            # 解除内存保护
            if pid in self.memory_protected:
                self.unprotect_memory(pid)
            if pid in self.frozen_processes:
                del self.frozen_processes[pid]
            self.status_label.setText(f"已解冻进程: {pid}")
            self.refresh_process_list()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解冻进程失败: {str(e)}")
    
    def suspend_process(self, pid):
        """挂起进程的所有线程"""
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hProcess:
            raise Exception("无法打开进程，可能需要管理员权限")
        
        try:
            # 获取所有线程ID
            thread_ids = self.get_process_threads(pid)
            
            # 挂起每个线程
            for tid in thread_ids:
                try:
                    hThread = win32api.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
                    if hThread:
                        ctypes.windll.kernel32.SuspendThread(hThread)
                        CloseHandle(hThread)
                except Exception as e:
                    continue  # 忽略单个线程挂起失败
        finally:
            CloseHandle(hProcess)
    
    def resume_process(self, pid):
        """恢复进程的所有线程"""
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hProcess:
            raise Exception("无法打开进程，可能需要管理员权限")
        
        try:
            # 获取所有线程ID
            thread_ids = self.get_process_threads(pid)
            
            # 恢复每个线程
            for tid in thread_ids:
                try:
                    hThread = win32api.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
                    if hThread:
                        ctypes.windll.kernel32.ResumeThread(hThread)
                        CloseHandle(hThread)
                except Exception as e:
                    continue  # 忽略单个线程恢复失败
        finally:
            CloseHandle(hProcess)
    
    def virtual_query_ex(self, hProcess, address):
        """查询进程内存信息"""
        mbi = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(mbi)
        bytes_returned = VirtualQueryEx(hProcess, address, ctypes.byref(mbi), size)
        if bytes_returned == 0:
            return None
        return mbi
    
    def protect_memory(self, pid=None):
        """保护进程内存（设置为只读）"""
        if not pid:
            selected_items = self.process_tree.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "警告", "请先选择进程")
                return
            pid = int(selected_items[0].text(0))
        
        if pid in self.memory_protected:
            QMessageBox.information(self, "提示", "该进程已受内存保护")
            return
        
        # 不保护系统关键进程
        if pid in [0, 4]:
            QMessageBox.warning(self, "警告", "不能保护系统关键进程")
            return
        
        # 添加内存保护警告
        reply = QMessageBox.question(self, "内存保护警告",
            "启用内存保护可能导致目标进程不稳定。确定继续吗？",
            QMessageBox.Yes | QMessageBox.No)
            
        if reply != QMessageBox.Yes:
            return
        
        try:
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not hProcess:
                raise Exception("无法打开进程，可能需要管理员权限")
            
            try:
                # 获取系统信息
                class SYSTEM_INFO(ctypes.Structure):
                    _fields_ = [
                        ("wProcessorArchitecture", wintypes.WORD),
                        ("wReserved", wintypes.WORD),
                        ("dwPageSize", wintypes.DWORD),
                        ("lpMinimumApplicationAddress", ctypes.c_void_p),
                        ("lpMaximumApplicationAddress", ctypes.c_void_p),
                        ("dwActiveProcessorMask", wintypes.DWORD),
                        ("dwNumberOfProcessors", wintypes.DWORD),
                        ("dwProcessorType", wintypes.DWORD),
                        ("dwAllocationGranularity", wintypes.DWORD),
                        ("wProcessorLevel", wintypes.WORD),
                        ("wProcessorRevision", wintypes.WORD)
                    ]
                
                system_info = SYSTEM_INFO()
                ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(system_info))
                
                # 遍历内存区域
                base_address = system_info.lpMinimumApplicationAddress
                old_protections = []
                
                while base_address < system_info.lpMaximumApplicationAddress:
                    mbi = self.virtual_query_ex(hProcess, base_address)
                    if not mbi:
                        break
                    
                    # 只处理已提交的可写内存页
                    if (mbi.State & 0x1000) and (mbi.Protect & (PAGE_READWRITE | 0x20 | 0x40)):
                        old_protect = wintypes.DWORD()
                        if VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, 
                                           PAGE_READONLY, ctypes.byref(old_protect)):
                            old_protections.append((mbi.BaseAddress, mbi.RegionSize, old_protect.value))
                    
                    # 移动到下一个内存区域
                    base_address = ctypes.c_void_p(ctypes.c_size_t(base_address) + mbi.RegionSize)
                
                if old_protections:
                    self.memory_protected[pid] = True
                    self.old_protections[pid] = old_protections
                    self.status_label.setText(f"已为进程 {pid} 启用内存保护")
                else:
                    QMessageBox.information(self, "提示", "未找到可保护的内存区域或保护失败")
            finally:
                CloseHandle(hProcess)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"内存保护失败: {str(e)}")
    
    def unprotect_memory(self, pid=None):
        """解除进程内存保护（恢复原始属性）"""
        if not pid:
            selected_items = self.process_tree.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "警告", "请先选择进程")
                return
            pid = int(selected_items[0].text(0))
        
        if pid not in self.memory_protected or pid not in self.old_protections:
            QMessageBox.information(self, "提示", "该进程未受内存保护")
            return
        
        try:
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not hProcess:
                raise Exception("无法打开进程，可能需要管理员权限")
            
            try:
                # 恢复原始内存保护属性
                for addr, size, protect in self.old_protections[pid]:
                    old_protect = wintypes.DWORD()
                    VirtualProtectEx(hProcess, addr, size, protect, ctypes.byref(old_protect))
                
                # 清除保护状态
                del self.memory_protected[pid]
                del self.old_protections[pid]
                self.status_label.setText(f"已解除进程 {pid} 的内存保护")
            finally:
                CloseHandle(hProcess)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解除内存保护失败: {str(e)}")
    
    def kill_process(self, pid):
        """终止指定进程"""
        # 不允许终止系统关键进程
        if pid in [0, 4]:
            QMessageBox.warning(self, "警告", "不能终止系统关键进程")
            return
            
        # 确认对话框
        reply = QMessageBox.question(self, "确认终止",
            f"确定要终止进程 PID: {pid} 吗？这可能导致数据丢失。",
            QMessageBox.Yes | QMessageBox.No)
            
        if reply != QMessageBox.Yes:
            return
        
        try:
            hProcess = OpenProcess(PROCESS_TERMINATE, False, pid)
            if not hProcess:
                raise Exception("无法打开进程，可能需要管理员权限")
            
            try:
                if not TerminateProcess(hProcess, 0):
                    raise Exception("终止进程失败")
                
                # 清除相关状态
                if pid in self.frozen_processes:
                    del self.frozen_processes[pid]
                if pid in self.memory_protected:
                    del self.memory_protected[pid]
                if pid in self.old_protections:
                    del self.old_protections[pid]
                
                self.status_label.setText(f"已终止进程: {pid}")
                self.refresh_process_list()
            finally:
                CloseHandle(hProcess)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"终止进程失败: {str(e)}")


if __name__ == "__main__":
    # 检查管理员权限
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    # 自动提权
    if not is_admin():
        # 重新以管理员权限运行
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)
    
    # 正常启动应用程序
    app = QApplication(sys.argv)
    try:
        window = SnowBurial()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"程序错误: {e}")
