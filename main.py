# -*- coding: utf-8 -*-
"""
输入法管理器 - Eel 后端入口（常驻服务模式）
- 不起浏览器窗口，仅监听 127.0.0.1:8000
- 窗口由 launcher.py 负责打开；关窗后服务继续驻留，实现秒开
- 打包后（--service）由 exe 拉起自身；脚本模式直接 python main.py 亦可
"""
import sys
import os

import eel

import ime_core
import backdoor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = ime_core.resource_path("web")
EEL_PORT = 8000


def _serialize(items):
    """把输入法条目序列化为前端友好结构（补充可展示字段）。"""
    out = []
    for it in items:
        out.append({
            "tip": it.get("tip", ""),
            "clsid": it.get("clsid", ""),
            "profile": it.get("profile", ""),
            "name": it.get("name", "未知输入法"),
            "tip_desc": it.get("tip_desc", ""),
            "dll": it.get("dll", ""),
            "lp_enable": it.get("lp_enable"),
            "in_use": it.get("in_use", False),
            "order": it.get("order"),
            "is_default": it.get("is_default", False),
        })
    return out


# ---------------------------------------------------------------- 查询类

@eel.expose
def get_all():
    """一次性返回全量数据：已安装 / 启用列表 / 锁定状态。"""
    try:
        installed = _serialize(ime_core.scan_installed_imes())
        enabled = _serialize(ime_core.get_imes())
        return {
            "ok": True,
            "installed": installed,
            "enabled": enabled,
            "disabled": ime_core.get_disabled(),
            "lock": ime_core.is_locked(),
            "langs": ime_core.list_languages(),
            "default_tip": ime_core.get_default_override(),
        }
    except Exception as e:
        return {"ok": False, "message": f"读取输入法信息失败: {e}"}


@eel.expose
def get_enabled():
    try:
        return {"ok": True, "enabled": _serialize(ime_core.get_imes())}
    except Exception as e:
        return {"ok": False, "message": str(e)}


@eel.expose
def get_installed():
    try:
        return {"ok": True, "installed": _serialize(ime_core.scan_installed_imes())}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ---------------------------------------------------------------- 操作类

@eel.expose
def apply_order(tips):
    """按传入 tip 顺序应用。"""
    try:
        return ime_core.apply_order(tips)
    except Exception as e:
        return {"ok": False, "message": f"应用顺序失败: {e}"}


@eel.expose
def set_default(tip):
    try:
        return ime_core.set_default(tip)
    except Exception as e:
        return {"ok": False, "message": f"设置默认输入法失败: {e}"}


@eel.expose
def remove_ime(tip):
    try:
        return ime_core.remove_ime(tip)
    except Exception as e:
        return {"ok": False, "message": f"移除输入法失败: {e}"}


@eel.expose
def enable_ime(clsid, profile, lcid="0x00000804"):
    try:
        return ime_core.enable_ime(clsid, profile, lcid)
    except Exception as e:
        return {"ok": False, "message": f"启用输入法失败: {e}"}


@eel.expose
def toggle_ime(tip):
    """开关输入法：关=停用保留（条目暗色），开=重新启用。"""
    try:
        return ime_core.toggle_ime(tip)
    except Exception as e:
        return {"ok": False, "message": f"切换输入法状态失败: {e}"}


@eel.expose
def remove_disabled(tip):
    """彻底移除停用记录（从列表删除，不再展示）。"""
    try:
        return ime_core.remove_disabled(tip)
    except Exception as e:
        return {"ok": False, "message": f"移除失败: {e}"}


# ---------------------------------------------------------------- 锁定守护

@eel.expose
def lock():
    try:
        return ime_core.lock_order()
    except Exception as e:
        return {"ok": False, "message": f"锁定失败: {e}"}


@eel.expose
def unlock():
    try:
        return ime_core.unlock_order()
    except Exception as e:
        return {"ok": False, "message": str(e)}


@eel.expose
def lock_status():
    try:
        return {"ok": True, **ime_core.is_locked(), "diff": ime_core.diff_lock(),
                "log": ime_core.get_watchdog_log()}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ---------------------------------------------------------------- 后门封堵

@eel.expose
def backdoor_status():
    """查询 SYSTEM 级后门检测状态。"""
    try:
        return backdoor.backdoor_status()
    except Exception as e:
        return {"ok": False, "message": str(e)}


@eel.expose
def backdoor_block():
    """手动封堵 SYSTEM 级后门（停服务 / 禁用自启 / 禁用任务）。"""
    try:
        return backdoor.block_backdoors()
    except Exception as e:
        return {"ok": False, "message": f"封堵后门失败: {e}"}


@eel.expose
def backdoor_unblock():
    """解除后门封堵（恢复服务自启与开机自启项）。"""
    try:
        return backdoor.unblock_backdoors()
    except Exception as e:
        return {"ok": False, "message": f"解除后门封堵失败: {e}"}


# ---------------------------------------------------------------- 启动

def _on_window_closed(page, sockets):
    """窗口关闭：保持服务常驻（配合 mode=None + close_callback，Eel 不会退出）。"""


def ensure_web_dir():
    """web 资源持久化：打包后资源位于临时 _MEIPASS，多实例/复用场景可能被清理，
    故首次启动复制到 %LOCALAPPDATA%\\ImeManager\\web 后统一使用持久副本。"""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    persist = os.path.join(base, "ImeManager", "web")
    src = ime_core.resource_path("web")
    if os.path.isdir(src) and os.path.abspath(src) != os.path.abspath(persist):
        try:
            os.makedirs(persist, exist_ok=True)
            src_mtime = os.path.getmtime(os.path.join(src, "index.html"))
            dst_mtime = os.path.getmtime(os.path.join(persist, "index.html")) \
                if os.path.exists(os.path.join(persist, "index.html")) else -1
            if src_mtime > dst_mtime:
                import shutil
                for name in os.listdir(src):
                    shutil.copy2(os.path.join(src, name), os.path.join(persist, name))
        except Exception as e:
            print("web 持久化失败，回退内置目录: %s" % e)
            return src
    return persist if os.path.isdir(persist) else src


def _port_in_use():
    import socket as _s
    try:
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex(("127.0.0.1", EEL_PORT)) == 0
    except OSError:
        return False


def _open_window():
    """用独立 Chrome 配置目录打开 App 窗口；命中已运行实例则复用窗口。"""
    import subprocess as _sp
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    profile_dir = os.path.join(base, "ImeManager", "chrome_profile")
    candidates = [
        r"C:\Program Files\Google\Chrome Dev\Application\chrome.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    browser = next((p for p in candidates if os.path.exists(p)), None)
    if not browser:
        print("未找到 Chrome/Edge，无法打开窗口")
        return
    os.makedirs(profile_dir, exist_ok=True)
    try:
        _sp.Popen(
            [browser, "--app=http://127.0.0.1:%d" % EEL_PORT,
             '--user-data-dir=%s' % profile_dir,
             "--window-size=1080,760",
             "--no-first-run", "--no-default-browser-check"],
            creationflags=0x08000000)
    except OSError as e:
        print("打开浏览器失败: %s" % e)


def main():
    web_dir = ensure_web_dir()
    eel.init(web_dir)
    # 端口已被占用：说明已有常驻服务，只开窗后退出（秒开路径）
    if _port_in_use():
        _open_window()
        return
    eel.start("index.html", mode=None, block=False,
              port=EEL_PORT, close_callback=_on_window_closed)
    # 首次启动：开窗 + 常驻
    _open_window()
    while True:
        eel.sleep(3600)


if __name__ == "__main__":
    main()
