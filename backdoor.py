# -*- coding: utf-8 -*-
r"""
输入法管理器 - SYSTEM 级后门封堵模块
====================================
背景：注册表 ACL 的 Deny 规则绑定当前用户 SID，仅能拦截用户级进程。
部分输入法（如千问）安装 SYSTEM 权限维护服务（LocalSystem），
可绕过用户级 ACL 直接改写输入法顺序/默认，导致"锁定失效"。

本模块负责：
1. 检测本机已知的 SYSTEM 级后门（维护服务 / 开机自启 / 计划任务）
2. 封堵：停止并禁用维护服务、禁用开机自启项、禁用相关计划任务
3. 解封：解除封堵（解锁时恢复）
4. 状态查询：供 UI 展示与 watchdog 兜底

封堵涉及系统级配置（服务、HKLM Run、计划任务），需要管理员权限；
通过 PowerShell Start-Process -Verb RunAs 触发 UAC 提权执行，
用户确认 UAC 后由提权进程完成写操作。
"""

import json
import os
import re
import subprocess
import sys
import time

_FROZEN = getattr(sys, "frozen", False)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 已知后门特征：厂商目录 / 服务名 / 自启名 / 任务名关键词
# 可扩展：新增输入法厂商时在此追加特征关键词。
BACKDOOR_KEYWORDS = (
    "qianwen",        # 千问输入法：QianwenIMEMaintenanceService / QianwenIMEServer / QianwenUpdaterTaskUser*
    # "doubao",       # 豆包如后续出现 SYSTEM 后门，在此追加
    # "wetype",
)

HKLM_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def resource_path(name):
    if _FROZEN:
        return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)), name)
    return os.path.join(BASE_DIR, name)


def _run_powershell(args, timeout=30):
    """静默运行 PowerShell，返回 (ok, stdout)。"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", args],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (r.stdout or "").strip()
        return (r.returncode == 0), out
    except Exception as e:
        return False, str(e)


def _scan_services():
    """枚举本机服务，返回列表 [{Name, State, StartMode, StartName, PathName}]。"""
    ok, out = _run_powershell(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,State,StartMode,StartName,PathName | "
        "ConvertTo-Json -Compress -Depth 2", timeout=60)
    if not ok or not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{
            "name": str(d.get("Name", "")),
            "state": str(d.get("State", "")),
            "start_mode": str(d.get("StartMode", "")),
            "start_name": str(d.get("StartName", "")),
            "path": str(d.get("PathName", "") or ""),
        } for d in data]
    except (ValueError, TypeError):
        return []


def _task_disabled(state):
    """计划任务状态兼容判定：Get-ScheduledTask State 可能返回枚举字符串或数字。"""
    s = str(state or "").strip().lower()
    return s in ("disabled", "1")


def _task_ready(state):
    """任务是否为启用/就绪状态（Ready 枚举为 3，字符串为 Ready）。"""
    s = str(state or "").strip().lower()
    return s in ("ready", "3")


def _is_backdoor_service(svc):
    """判定服务是否为后门：LocalSystem 身份 + 关键词命中。"""
    name = svc.get("name", "")
    path = svc.get("path", "")
    start_name = svc.get("start_name", "")
    low = (name + " " + path).lower()
    if not any(k in low for k in BACKDOOR_KEYWORDS):
        return False
    # 只针对 SYSTEM/LocalSystem 身份的服务（用户级进程 ACL 已能拦截）
    if "localsystem" not in start_name.lower() and "system" != start_name.lower() and not re.search(r"\\system$", start_name, re.I):
        return False
    return True


def _scan_run_values():
    """枚举 HKLM Run 开机自启值。"""
    import winreg
    out = []
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HKLM_RUN, 0,
                           winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        i = 0
        while True:
            try:
                n, v, _ = winreg.EnumValue(k, i)
                out.append({"name": str(n), "value": str(v)})
                i += 1
            except OSError:
                break
        winreg.CloseKey(k)
    except OSError:
        pass
    return out


def _scan_tasks():
    """枚举计划任务（仅查询，无副作用）。"""
    ok, out = _run_powershell(
        "Get-ScheduledTask | Where-Object { $_.TaskName -match 'Qianwen' } | "
        "Select-Object TaskName,State | ConvertTo-Json -Compress", timeout=60)
    if not ok or not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return [{"name": str(d.get("TaskName", "")), "state": str(d.get("State", ""))} for d in data]
    except (ValueError, TypeError):
        return []


def scan_backdoors():
    """检测全部后门，返回 {services: [...], run: [...], tasks: [...], any: bool}。"""
    services = [s for s in _scan_services() if _is_backdoor_service(s)]
    run = [r for r in _scan_run_values() if any(k in (r.get("name", "") + " " + r.get("value", "")).lower() for k in BACKDOOR_KEYWORDS)]
    tasks = _scan_tasks()
    return {
        "services": services,
        "run": run,
        "tasks": tasks,
        "any": bool(services or run or tasks),
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _is_admin():
    """当前进程是否管理员权限。"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevate_ps1(action, script=None):
    """通过 UAC 提权运行 backdoor_helper.ps1。返回 (ok, msg)。"""
    helper = script or resource_path("backdoor_helper.ps1")
    if not os.path.exists(helper):
        return False, "未找到 backdoor_helper.ps1"
    quoted = '"%s"' % helper
    ps_args = "-NoProfile -ExecutionPolicy Bypass -File {0} -Action {1}".format(quoted, action)
    # Start-Process -Verb RunAs 触发 UAC；-Wait 等待完成
    cmd = ("$p = Start-Process -FilePath 'powershell' -ArgumentList '{0}' "
           "-Verb RunAs -Wait -PassThru; exit $p.ExitCode").format(ps_args.replace("'", "''"))
    ok, out = _run_powershell(cmd, timeout=180)
    return ok, (out or ("提权执行完成" if ok else "提权执行失败或用户取消"))


def block_backdoors(script=None):
    """封堵全部后门：停服务 + 禁用自启 + 禁用任务。返回封堵报告。"""
    scan = scan_backdoors()
    report = {"blocked_services": [], "blocked_run": [], "blocked_tasks": [], "skipped": []}

    if not scan["any"]:
        return {"ok": True, "message": "未检测到需要封堵的后门", **report}

    # 需要管理员权限；当前非管理员时走 UAC 提权执行 helper
    if not _is_admin():
        ok, msg = _elevate_ps1("block", script)
        if not ok:
            return {"ok": False, "message": "封堵失败（需要管理员权限）：" + msg, **report}
        # 提权完成后刷新检测确认状态
        scan2 = scan_backdoors()
        report["blocked_services"] = [s["name"] for s in scan2["services"] if s.get("state", "").lower() != "running"]
        report["blocked_run"] = [r["name"] for r in scan2["run"]]
        report["blocked_tasks"] = [t["name"] for t in scan2["tasks"] if not _task_ready(t.get("state"))]
        return {"ok": True, "message": "已封堵 SYSTEM 级后门（UAC 提权执行）", **report}

    # 当前已是管理员：直接在本进程执行
    import winreg
    blocked_svc, blocked_run, blocked_tasks = [], [], []
    for s in scan["services"]:
        try:
            _run_powershell("Stop-Service -Name '{0}' -Force -ErrorAction SilentlyContinue; "
                            "Set-Service -Name '{0}' -StartupType Disabled".format(s["name"].replace("'", "''")), timeout=60)
            blocked_svc.append(s["name"])
        except Exception as e:
            report["skipped"].append("service:" + s["name"] + ":" + str(e))
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HKLM_RUN, 0,
                           winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
        for r in scan["run"]:
            try:
                val = winreg.QueryValueEx(k, r["name"])[0]
                winreg.SetValueEx(k, r["name"] + ".disabled_by_ime_manager", 0, winreg.REG_SZ, val)
                winreg.DeleteValue(k, r["name"])
                blocked_run.append(r["name"])
            except OSError:
                report["skipped"].append("run:" + r["name"])
        winreg.CloseKey(k)
    except OSError as e:
        report["skipped"].append("run_key:" + str(e))
    for t in scan["tasks"]:
        try:
            _run_powershell("Disable-ScheduledTask -TaskName '{0}' -ErrorAction SilentlyContinue".format(t["name"].replace("'", "''")), timeout=60)
            blocked_tasks.append(t["name"])
        except Exception as e:
            report["skipped"].append("task:" + t["name"] + ":" + str(e))

    report.update(blocked_services=blocked_svc, blocked_run=blocked_run, blocked_tasks=blocked_tasks)
    return {"ok": True, "message": "已封堵 SYSTEM 级后门", **report}


def unblock_backdoors(script=None):
    """解除封堵：恢复服务自启、恢复 Run 自启值、启用计划任务。"""
    scan = scan_backdoors()
    report = {"restored_services": [], "restored_run": [], "restored_tasks": [], "skipped": []}
    # 仅处理当前处于"已封堵"状态的对象：服务 Disabled、Run 值带 .disabled_by_ime_manager、任务 Disabled
    services = [s for s in _scan_services() if s.get("name", "").lower() and
                any(k in s.get("name", "").lower() for k in BACKDOOR_KEYWORDS) and
                s.get("start_mode", "").lower() == "disabled"]
    run = [r for r in _scan_run_values() if ".disabled_by_ime_manager" in r.get("name", "").lower()]
    tasks = [t for t in _scan_tasks() if _task_disabled(t.get("state"))]

    if not (services or run or tasks):
        return {"ok": True, "message": "没有需要解除封堵的后门", **report}

    if not _is_admin():
        ok, msg = _elevate_ps1("unblock", script)
        if not ok:
            return {"ok": False, "message": "解除封堵失败（需要管理员权限）：" + msg, **report}
        return {"ok": True, "message": "已解除后门封堵（UAC 提权执行）", **report}

    import winreg
    restored_svc, restored_run, restored_tasks = [], [], []
    for s in services:
        try:
            _run_powershell("Set-Service -Name '{0}' -StartupType Auto".format(s["name"].replace("'", "''")), timeout=60)
            restored_svc.append(s["name"])
        except Exception as e:
            report["skipped"].append("service:" + s["name"] + ":" + str(e))
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HKLM_RUN, 0,
                           winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
        for r in run:
            base = r["name"].replace(".disabled_by_ime_manager", "")
            try:
                val = winreg.QueryValueEx(k, r["name"])[0]
                winreg.SetValueEx(k, base, 0, winreg.REG_SZ, val)
                winreg.DeleteValue(k, r["name"])
                restored_run.append(base)
            except OSError:
                report["skipped"].append("run:" + r["name"])
        winreg.CloseKey(k)
    except OSError as e:
        report["skipped"].append("run_key:" + str(e))
    for t in tasks:
        try:
            _run_powershell("Enable-ScheduledTask -TaskName '{0}' -ErrorAction SilentlyContinue".format(t["name"].replace("'", "''")), timeout=60)
            restored_tasks.append(t["name"])
        except Exception as e:
            report["skipped"].append("task:" + t["name"] + ":" + str(e))

    report.update(restored_services=restored_svc, restored_run=restored_run, restored_tasks=restored_tasks)
    return {"ok": True, "message": "已解除后门封堵", **report}


def backdoor_status():
    """UI 展示用状态：扫描结果 + 是否全部已封堵。"""
    scan = scan_backdoors()
    services = scan["services"]
    run = scan["run"]
    tasks = scan["tasks"]
    # 已封堵判定：服务已停止/禁用、Run 值已改名、任务已禁用
    blocked = True
    for s in services:
        if s.get("state", "").lower() == "running" or s.get("start_mode", "").lower() != "disabled":
            blocked = False
    for r in run:
        if ".disabled_by_ime_manager" not in r.get("name", "").lower():
            blocked = False
    for t in tasks:
        if _task_ready(t.get("state")):
            blocked = False
    return {
        "ok": True,
        "scanned_at": scan["scanned_at"],
        "services": services,
        "run": run,
        "tasks": tasks,
        "any": scan["any"],
        "blocked": blocked,
    }


if __name__ == "__main__":
    st = backdoor_status()
    print(json.dumps(st, ensure_ascii=False, indent=2))
