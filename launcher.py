# -*- coding: utf-8 -*-
"""
launcher.py - 输入法管理器启动器（秒开版）
职责：
  1. 检测 8000 端口：服务已在 → 直接开窗（秒开）；未在 → 拉起常驻服务并等待就绪
  2. 打开独立 Chrome 配置目录（--user-data-dir），不污染日常浏览器配置
  3. 打包后入口：exe 无参 = 启动器；exe --service = 常驻服务（由启动器拉起自身）
"""
import ctypes
import os
import socket
import subprocess
import sys
import time

HOST = "127.0.0.1"
PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "launcher_error.log")
PROFILE_DIR = os.path.join(BASE_DIR, "chrome_profile")
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
WINDOW_SIZE = "1080,760"

BROWSER_CANDIDATES = [
    r"C:\Program Files\Google\Chrome Dev\Application\chrome.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]


def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def port_in_use():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex((HOST, PORT)) == 0
    except OSError:
        return False


def listening_pids():
    """返回监听 8000 端口的 PID 列表"""
    pids = set()
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                           creationflags=CREATE_NO_WINDOW, timeout=10)
        for line in r.stdout.splitlines():
            if ":8000" in line and "LISTENING" in line.upper():
                parts = line.split()
                if parts and parts[-1].isdigit():
                    pids.add(int(parts[-1]))
    except Exception as e:
        log("netstat 查询失败: %s" % e)
    return pids


def process_name(pid):
    try:
        r = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=10)
        lines = [ln for ln in r.stdout.strip().splitlines() if ln.strip()]
        if lines:
            return lines[0].split('","')[0].strip('"')
    except Exception:
        pass
    return ""


def kill_pid(pid):
    """仅当进程名为 pythonw 时强制结束，防止误杀其他程序"""
    name = process_name(pid)
    if not name or not name.lower().startswith("pythonw"):
        log("跳过非 pythonw 占用进程 PID=%d (%s)" % (pid, name or "未知"))
        return False
    try:
        PROCESS_TERMINATE = 0x0001
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h:
            log("OpenProcess 失败 PID=%d" % pid)
            return False
        k32.TerminateProcess(h, 1)
        k32.CloseHandle(h)
        log("已结束残留实例 PID=%d (%s)" % (pid, name))
        return True
    except Exception as e:
        log("结束进程失败 PID=%d: %s" % (pid, e))
        return False


def start_service():
    """拉起常驻服务（脚本模式: python main.py；打包模式: exe --service）。"""
    try:
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--service"]
        else:
            cmd = [sys.executable, "main.py"]
        return subprocess.Popen(cmd, cwd=BASE_DIR,
                                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except OSError as e:
        log("拉起常驻服务失败: %s" % e)
        return None


def find_browser():
    for p in BROWSER_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def open_window():
    """用独立配置目录打开 App 窗口，命中已运行实例则复用窗口。"""
    browser = find_browser()
    if not browser:
        log("未找到 Chrome/Edge，无法打开窗口")
        return False
    url = "http://%s:%d" % (HOST, PORT)
    os.makedirs(PROFILE_DIR, exist_ok=True)
    try:
        subprocess.Popen(
            [browser, "--app=%s" % url,
             '--user-data-dir=%s' % PROFILE_DIR,
             "--window-size=%s" % WINDOW_SIZE,
             "--no-first-run", "--no-default-browser-check"],
            creationflags=CREATE_NO_WINDOW)
        log("已打开窗口: %s" % browser)
        return True
    except OSError as e:
        log("打开浏览器失败: %s" % e)
        return False


def wait_port(timeout=20.0, interval=0.3):
    """轮询等待 8000 端口就绪，返回是否就绪。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_in_use():
            return True
        time.sleep(interval)
    return False


def main():
    log("boot frozen=%s exe=%s base=%s cwd=%s" % (
        getattr(sys, "frozen", False), sys.executable, BASE_DIR, os.getcwd()))
    if port_in_use():
        log("服务已在运行，直接开窗")
    else:
        proc = start_service()
        if proc is None:
            log("启动失败：无法拉起常驻服务")
            return
        if not wait_port():
            log("启动异常：等待 8000 端口超时")
            return
        log("常驻服务已就绪 (PID=%d)" % proc.pid)
    open_window()


if __name__ == "__main__":
    if "--service" in sys.argv:
        # 打包模式：exe --service = 常驻服务（不起窗），由无参启动器拉起
        import main as ime_main
        ime_main.run_server()
    else:
        main()
