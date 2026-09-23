# -*- coding: utf-8 -*-
r"""
输入法管理器 - 核心逻辑（通用版）
=================================
通用化设计，不依赖单台机器的固定语言 / 固定输入法集合：

1. 启动自动检测本机所有已安装输入法
   - 枚举 HKLM\SOFTWARE\Microsoft\CTF\TIP（系统注册的全部 TSF 文本输入处理器）
   - 通过 LanguageProfile 的 Description + DLL 版本信息解析真实名称
2. 支持调整顺序 / 删减（从启用列表隐藏）/ 重新启用
   - 启用列表与顺序: HKCU\Control Panel\International\User Profile\<Lang>
   - CTF 排序:        HKCU\Software\Microsoft\CTF\SortOrder\AssemblyItem\<LCID>\{34745C63-...}\0000000x
3. 支持默认输入法
   - 全局默认: HKCU\Control Panel\International\User Profile\InputMethodOverride
4. 防篡改（顺序锁定 + 自动守护）
   - 保存锁定快照，后台 watchdog 轮询注册表，输入法更新抢占首位时自动恢复顺序
"""

import functools
import json
import os
import re
import subprocess
import sys
import threading
import time
import winreg

PROFILE_KEY = r"Control Panel\International\User Profile"
CTF_SORT_BASE = r"Software\Microsoft\CTF\SortOrder\AssemblyItem"
CTF_IME_CATEGORY = "{34745C63-B2F0-4784-8B67-5E12C8701A31}"
TIP_HKLM = r"SOFTWARE\Microsoft\CTF\TIP"
CTF_KEY = r"Software\Microsoft\CTF"

_FROZEN = getattr(sys, "frozen", False)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def resource_path(name):
    """只读资源（acl_helper.ps1 等）：打包后从 PyInstaller 临时解包目录取。"""
    if _FROZEN:
        return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)), name)
    return os.path.join(BASE_DIR, name)


def data_path(name):
    """可写数据（锁定快照/日志/profile 等）：打包后放 exe 旁，避免写入临时目录。"""
    if _FROZEN:
        return os.path.join(os.path.dirname(sys.executable), name)
    return os.path.join(BASE_DIR, name)


LOCK_FILE = data_path("ime_lock.json")
DISABLED_FILE = data_path("ime_disabled.json")
WATCHDOG_INTERVAL = 5.0          # 守护轮询间隔（秒）
WATCHDOG_LOG = data_path("ime_watchdog.log")

# 显示名中文化映射（仅影响展示，不影响注册表操作）
DISPLAY_NAME_MAP = {
    "Microsoft Pinyin": "微软拼音",
    "Microsoft IME": "微软输入法",
    "WeType": "微信输入法",
}

# 友好名称映射：覆盖各输入法在 TIP Description / DLL 版本信息中常见的
# 内部英文名，统一映射为面向用户的友好名称。
FRIENDLY_NAME_MAP = {
    "豆包输入法": "豆包输入法",
    "Doubao IME": "豆包输入法",
    "Doubao IME TSF Stub": "豆包输入法",
    "千问输入法": "千问输入法",
    "QianwenIME": "千问输入法",
    "WeType": "微信输入法",
    "微信输入法": "微信输入法",
    "WPS输入法": "WPS输入法",
    "WPS Office": "WPS输入法",
    "Microsoft Pinyin": "微软拼音",
    "Microsoft IME": "微软输入法",
    "微软拼音": "微软拼音",
    "微软输入法": "微软输入法",
}

# 系统辅助 TIP 特征关键词：这些不是用户输入法，扫描时应过滤
AUX_TIP_KEYWORDS = (
    "speech", "tablet pc", "correction", "transitory", "softkbd",
    "cactiveimm", "tf_", "handwriting", "voice", "dictionary",
    "table driven", "imm", "触控", "手写", "语音", "软键盘",
)

_lock_state = {"locked": False, "stop": False, "thread": None, "lang": None}


# ---------------------------------------------------------------- 基础工具

def _open_key(root, path, writable=False, view=None):
    access = winreg.KEY_READ | (winreg.KEY_WRITE if writable else 0)
    if view:
        return winreg.OpenKey(root, path, 0, access | view)
    try:
        return winreg.OpenKey(root, path, 0, access)
    except OSError:
        try:
            return winreg.OpenKey(root, path, 0, access | winreg.KEY_WOW64_64KEY)
        except OSError:
            return winreg.OpenKey(root, path, 0, access | winreg.KEY_WOW64_32KEY)


def _enum_subkeys(root, path):
    try:
        k = _open_key(root, path)
    except OSError:
        return []
    out = []
    i = 0
    while True:
        try:
            out.append(winreg.EnumKey(k, i))
            i += 1
        except OSError:
            break
    winreg.CloseKey(k)
    return out


def _enum_values(root, path):
    try:
        k = _open_key(root, path)
    except OSError:
        return []
    out = []
    i = 0
    while True:
        try:
            n, v, t = winreg.EnumValue(k, i)
            out.append((n, v, t))
            i += 1
        except OSError:
            break
    winreg.CloseKey(k)
    return out


def _parse_tip(tip):
    """解析 '0804:{CLSID}{ProfileGUID}' -> (lcid, clsid, profile)。"""
    tip = tip.strip()
    if ":" not in tip:
        return None
    lcid, rest = tip.split(":", 1)
    m = re.match(r"\{([0-9A-Fa-f-]+)\}\{([0-9A-Fa-f-]+)\}", rest)
    if m:
        return lcid, "{" + m.group(1) + "}", "{" + m.group(2) + "}"
    return None


def _expand_env(path):
    return os.path.expandvars(path) if path else path


# ---------------------------------------------------------------- 名称解析

def _get_dll_ver(dll):
    """读取 DLL/EXE 版本信息，返回 (FileDescription, ProductName) 或 None。

    纯 ctypes 实现（kernel32 version.dll），不拉起任何子进程，避免闪现控制台窗口。
    """
    if not dll or not os.path.exists(dll):
        return None
    try:
        import ctypes
        from ctypes import wintypes
        size = ctypes.windll.version.GetFileVersionInfoSizeW(dll, None)
        if size == 0:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(dll, 0, size, buf):
            return None
        trans = ctypes.c_void_p()
        trans_len = wintypes.UINT()
        if not ctypes.windll.version.VerQueryValueW(
                buf, r"\VarFileInfo\Translation",
                ctypes.byref(trans), ctypes.byref(trans_len)):
            return None
        words = ctypes.cast(trans, ctypes.POINTER(wintypes.WORD * 2)).contents
        sub = "%04x%04x" % (words[0], words[1])
        res = {}
        for name in ("FileDescription", "ProductName"):
            key = r"\StringFileInfo\%s\%s" % (sub, name)
            pp = ctypes.c_void_p()
            plen = wintypes.UINT()
            if ctypes.windll.version.VerQueryValueW(
                    buf, key, ctypes.byref(pp), ctypes.byref(plen)):
                res[name] = ctypes.wstring_at(pp.value)
        fd = res.get("FileDescription")
        pn = res.get("ProductName")
        if fd or pn:
            return ((fd or "").strip(), (pn or "").strip())
    except Exception:
        pass
    return None


def _clsid_default_name(clsid):
    """从 HKCR\CLSID 读取默认显示名。"""
    for root, base in (
        (winreg.HKEY_CLASSES_ROOT, "CLSID"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Classes\CLSID"),
    ):
        try:
            k = winreg.OpenKey(root, base + "\\" + clsid)
            try:
                v, _ = winreg.QueryValueEx(k, None)
                if v:
                    return str(v)
            finally:
                winreg.CloseKey(k)
        except OSError:
            continue
    return None


def _clsid_dll(clsid):
    """查找 CLSID 对应的 DLL/EXE 路径（InprocServer32 / LocalServer32）。"""
    for root, base in (
        (winreg.HKEY_CLASSES_ROOT, "CLSID"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
    ):
        for sub in ("InprocServer32", "LocalServer32"):
            try:
                k = winreg.OpenKey(root, base + "\\" + clsid + "\\" + sub)
                try:
                    v, _ = winreg.QueryValueEx(k, None)
                    if v:
                        return _expand_env(str(v).strip('"'))
                finally:
                    winreg.CloseKey(k)
            except OSError:
                continue
    return None


def resolve_ime_name(clsid, tip_desc=None, dll_hint=None):
    """
    解析输入法显示名称，优先级：
    1. 友好名称映射（TIP Description / DLL 版本信息 / 中文化映射）
    2. TIP LanguageProfile Description
    3. DLL 版本信息 FileDescription / ProductName
    4. CLSID 默认名
    5. 兜底返回 CLSID
    """
    cands = []
    if tip_desc:
        cands.append(tip_desc)
    if dll_hint:
        cands.append(dll_hint)

    # 1) 友好名称映射（最高优先，如 WeType -> 微信输入法、Doubao -> 豆包输入法）
    for c in cands:
        if c in FRIENDLY_NAME_MAP:
            return FRIENDLY_NAME_MAP[c]
    if tip_desc in DISPLAY_NAME_MAP:
        return DISPLAY_NAME_MAP[tip_desc]

    # 2) DLL 版本信息（比内部 Description 更友好时使用）
    dll = dll_hint or _clsid_dll(clsid)
    if not dll:
        # TIP IconFile 也是 DLL 来源
        try:
            base = TIP_HKLM + "\\" + clsid + r"\LanguageProfile"
            for lg in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
                for p in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg):
                    for n, v, _ in _enum_values(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg + "\\" + p):
                        if n == "IconFile" and v:
                            dll = _expand_env(str(v))
        except OSError:
            pass
    if dll:
        ver = _get_dll_ver(dll)
        if ver:
            fd, pn = ver
            for cand in (fd, pn):
                if cand and cand in FRIENDLY_NAME_MAP:
                    return FRIENDLY_NAME_MAP[cand]
            for cand in (fd, pn):
                if cand and not re.match(r"^(textservice|CImeServerChs|.*\.dll|.*\.exe|$)", cand, re.I):
                    return cand

    # 3) Description
    if tip_desc:
        return tip_desc

    # 4) CLSID 名
    name = _clsid_default_name(clsid)
    if name:
        return name

    return clsid


# ---------------------------------------------------------------- 扫描已安装

def scan_installed_imes():
    """
    扫描本机所有已安装输入法（HKLM TIP），返回:
    [{clsid, tip_desc, dll, name, enabled(lp), in_use(是否在启用列表)}]
    """
    result = []
    used_tips = set()
    for lang in list_languages():
        for it in _read_profile_imes(lang):
            used_tips.add(it["tip"])

    for clsid in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, TIP_HKLM):
        # 读取该 TIP 下所有 LanguageProfile 的 Description / Enable / IconFile
        tip_desc = None
        lp_enable = None
        lp_lcid = None
        lp_profile = None
        base = TIP_HKLM + "\\" + clsid + r"\LanguageProfile"
        for lg in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
            for p in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg):
                for n, v, _ in _enum_values(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg + "\\" + p):
                    if n == "Description" and not tip_desc:
                        tip_desc = str(v)
                    elif n == "Enable" and lp_enable is None:
                        lp_enable = int(v)
                    elif n == "IconFile" and not lp_lcid:
                        lp_lcid = lg
                if lp_profile is None:
                    lp_profile = p
                if lp_lcid is None:
                    lp_lcid = lg

        # 构成 TIP 字符串（用于匹配 User Profile 启用列表）
        tip_str = None
        if lp_lcid and lp_profile:
            tip_str = f"{lp_lcid}:{clsid}{lp_profile}"
            # 规范化 lcid 为 0x 格式
            try:
                tip_str = f"0x{int(lp_lcid, 16):08X}:{clsid}{lp_profile}"
            except (ValueError, TypeError):
                tip_str = f"{lp_lcid}:{clsid}{lp_profile}"

        dll = _clsid_dll(clsid)
        name = resolve_ime_name(clsid, tip_desc, dll_hint=dll)
        in_use = any(t.lower() == (tip_str or "").lower() or
                     (tip_str and _parse_tip(t) and _parse_tip(t)[1].lower() == clsid.lower())
                     for t in used_tips)

        # 过滤系统辅助 TIP（语音识别 / 手写 / 软键盘 / 触控等，非用户输入法）
        probe = ((tip_desc or "") + " " + name + " " + clsid).lower()
        is_aux = any(kw in probe for kw in AUX_TIP_KEYWORDS)
        if is_aux and not in_use and not lp_enable:
            continue
        if not tip_desc and not lp_enable and not in_use:
            # 无描述且未启用的内部 TIP（如 {0000897b}），非用户输入法，跳过
            continue
        if (not lp_lcid or str(lp_lcid).lower() in ("0x00000000", "0")) and not in_use:
            # LanguageProfile 无有效语言代码（系统内部组件），非用户输入法，跳过
            continue
        # 通用化显示过滤：未启用的输入法仅保留简体中文(0804)相关，
        # 避免把系统预装的多语言 IME（日文/仓颉/越南语等）全部罗列
        if not in_use and not _is_cn_relevant(lp_lcid, tip_desc, name):
            continue
        # 未启用的微软系统内置 IME（Windows 自带组件残留，非用户安装）不展示，
        # 避免已安装列表混入多个系统 TSF 实例（用户只关心自己装的那几个）
        if not in_use and name in ("微软输入法", "微软拼音"):
            continue

        result.append({
            "clsid": clsid,
            "tip_desc": tip_desc,
            "dll": dll or "",
            "name": name,
            "lp_enable": lp_enable,
            "lp_lcid": lp_lcid or "",
            "profile": lp_profile or "",
            "tip": tip_str or "",
            "in_use": in_use,
        })
    return result


# ---------------------------------------------------------------- 读取启用列表

def list_languages():
    """列出 User Profile 下所有语言子键。"""
    return _enum_subkeys(winreg.HKEY_CURRENT_USER, PROFILE_KEY)


def _read_profile_imes(lang):
    """读取某语言下全部已启用输入法（按顺序号排序）。"""
    items = []
    path = PROFILE_KEY + "\\" + lang
    for name, value, vtype in _enum_values(winreg.HKEY_CURRENT_USER, path):
        if name == "CachedLanguageName" or ":" not in name:
            continue
        parsed = _parse_tip(name)
        if not parsed:
            continue
        try:
            order = int(value)
        except (TypeError, ValueError):
            continue
        lcid, clsid, profile = parsed
        items.append({
            "tip": name,
            "lcid": lcid,
            "clsid": clsid,
            "profile": profile,
            "order": order,
            "name": resolve_ime_name(clsid, _tip_description(clsid)),
        })
    items.sort(key=lambda x: x["order"])
    return items


def _tip_description(clsid):
    """从 HKLM TIP 读取某 CLSID 的 LanguageProfile Description。"""
    base = TIP_HKLM + "\\" + clsid + r"\LanguageProfile"
    for lg in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
        for p in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg):
            for n, v, _ in _enum_values(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg + "\\" + p):
                if n == "Description":
                    return str(v)
    return None


def get_default_override():
    try:
        k = _open_key(winreg.HKEY_CURRENT_USER, PROFILE_KEY)
        try:
            v, _ = winreg.QueryValueEx(k, "InputMethodOverride")
            return v
        finally:
            winreg.CloseKey(k)
    except OSError:
        return None


def get_imes(lang=None):
    """获取启用输入法列表；lang 为空时使用默认（第一个含 TIP 的语言）。"""
    if lang is None:
        langs = list_languages()
        lang = langs[0] if langs else "zh-Hans-CN"
    items = _read_profile_imes(lang)
    override = get_default_override()
    for it in items:
        it["is_default"] = (it["tip"] == override)
        it["lang"] = lang
    return items


# ---------------------------------------------------------------- ACL 固化（方案A）

ACL_SCRIPT = resource_path("acl_helper.ps1")


def _acl_run(action):
    """静默调用 acl_helper.ps1（CREATE_NO_WINDOW，不闪窗）。返回 (ok, payload)。"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", ACL_SCRIPT, "-Action", action],
            capture_output=True, text=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (r.stdout or "").strip()
        if r.returncode != 0:
            return False, (r.stderr or out or "ACL 操作失败")
        return True, out
    except Exception as e:
        return False, str(e)


def acl_status():
    """查询顺序键 ACL 固化状态。"""
    ok, out = _acl_run("status")
    if not ok:
        return {"ok": False, "message": out}
    try:
        data = json.loads(out)
        return {"ok": True, **data}
    except (ValueError, TypeError):
        return {"ok": False, "message": "ACL 状态解析失败"}


def _acl_locked():
    st = acl_status()
    return bool(st.get("ok") and (st.get("root_locked") or st.get("profile_locked") or st.get("ctf_locked") or st.get("subkeys_locked")))


def lock_acls():
    ok, out = _acl_run("lock")
    if not ok:
        return {"ok": False, "message": out}
    return {"ok": True, "message": "已固化注册表 ACL，顺序键拒绝第三方写入"}


def unlock_acls():
    ok, out = _acl_run("unlock")
    if not ok:
        return {"ok": False, "message": out}
    return {"ok": True, "message": "已解除注册表 ACL 固化"}


def acl_guard(func):
    """装饰器：写顺序/默认前自动解除 ACL，写完后按原状态重新固化。"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        was_locked = _acl_locked()
        if was_locked:
            unlock_acls()
        try:
            return func(*args, **kwargs)
        finally:
            if was_locked:
                lock_acls()
    return wrapper


# ---------------------------------------------------------------- 顺序 / 默认

def _write_ctf_order(lcid, ordered_tips):
    """重建 CTF SortOrder 子键顺序，与 ordered_tips 一致。"""
    try:
        lcid_hex = f"0x{int(lcid, 16):08X}"
    except (ValueError, TypeError):
        lcid_hex = f"0x{int(lcid):08X}" if str(lcid).isdigit() else None
    if not lcid_hex:
        return False
    base = f"{CTF_SORT_BASE}\\{lcid_hex}\\{CTF_IME_CATEGORY}"

    old_keys = _enum_subkeys(winreg.HKEY_CURRENT_USER, base)
    old_keys.sort()

    # 建立 tip -> (clsid, profile)
    tip_map = {}
    for tip in ordered_tips:
        p = _parse_tip(tip)
        if p:
            tip_map[tip] = p

    # 新建临时键并写值
    tmp_names = []
    for idx, tip in enumerate(ordered_tips):
        if tip not in tip_map:
            continue
        _, clsid, profile = tip_map[tip]
        tmp = f"tmp{idx:08d}"
        try:
            nk = winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + "\\" + tmp)
            winreg.SetValueEx(nk, "CLSID", 0, winreg.REG_SZ, clsid)
            winreg.SetValueEx(nk, "KeyboardLayout", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(nk, "Profile", 0, winreg.REG_SZ, profile)
            winreg.CloseKey(nk)
            tmp_names.append(tmp)
        except OSError:
            continue

    # 删旧键
    for sub in old_keys:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + "\\" + sub)
        except OSError:
            pass

    # 临时键 -> 00000000..
    for idx, tmp in enumerate(tmp_names):
        src = base + "\\" + tmp
        dst = base + "\\" + f"{idx:08d}"
        try:
            data = _enum_values(winreg.HKEY_CURRENT_USER, src)
            nk = winreg.CreateKey(winreg.HKEY_CURRENT_USER, dst)
            for n, v, t in data:
                try:
                    winreg.SetValueEx(nk, n, 0, t, v)
                except OSError:
                    pass
            winreg.CloseKey(nk)
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, src)
            except OSError:
                pass
        except OSError:
            continue
    return True


@acl_guard
def apply_order(tips, lang=None):
    """应用输入法顺序：User Profile 顺序号 + CTF SortOrder。"""
    if lang is None:
        langs = list_languages()
        lang = langs[0] if langs else "zh-Hans-CN"
    if not tips:
        return {"ok": False, "message": "输入法列表为空"}

    results = []
    path = PROFILE_KEY + "\\" + lang
    try:
        k = _open_key(winreg.HKEY_CURRENT_USER, path, writable=True)
        for idx, tip in enumerate(tips, start=1):
            try:
                winreg.SetValueEx(k, tip, 0, winreg.REG_DWORD, idx)
                results.append(f"顺序 #{idx}: {tip}")
            except OSError as e:
                results.append(f"写入失败 {tip}: {e}")
        winreg.CloseKey(k)
    except OSError as e:
        return {"ok": False, "message": f"打开 User Profile 失败: {e}"}

    lcid = "0804"
    for tip in tips:
        p = _parse_tip(tip)
        if p:
            lcid = p[0]
            break
    try:
        ok = _write_ctf_order(lcid, tips)
        results.append("CTF SortOrder 已同步" if ok else "CTF SortOrder 无变更")
    except OSError as e:
        results.append(f"CTF SortOrder 同步失败: {e}")

    _notify_ctf()
    return {"ok": True, "message": "顺序已应用", "lang": lang, "results": results}


@acl_guard
def set_default(tip, lang=None):
    """设置全局默认输入法：写 InputMethodOverride + 移到首位。"""
    try:
        k = _open_key(winreg.HKEY_CURRENT_USER, PROFILE_KEY, writable=True)
        winreg.SetValueEx(k, "InputMethodOverride", 0, winreg.REG_SZ, tip)
        winreg.CloseKey(k)
    except OSError as e:
        return {"ok": False, "message": f"设置 InputMethodOverride 失败: {e}"}

    imes = get_imes(lang)
    tips = [it["tip"] for it in imes]
    if tip in tips:
        tips.remove(tip)
        tips.insert(0, tip)
        r = apply_order(tips, lang)
        r["message"] = f"已设「{_name_of(tip, lang)}」为全局默认输入法"
        return r
    return {"ok": True, "message": "已设默认输入法"}


def _name_of(tip, lang=None):
    try:
        for it in get_imes(lang):
            if it["tip"] == tip:
                return it["name"]
    except OSError:
        pass
    return tip


# ---------------------------------------------------------------- 删减 / 启用

@acl_guard
def remove_ime(tip, lang=None):
    """从启用列表移除输入法（不卸载程序）。"""
    if lang is None:
        langs = list_languages()
        lang = langs[0] if langs else "zh-Hans-CN"
    path = PROFILE_KEY + "\\" + lang
    results = []

    try:
        k = _open_key(winreg.HKEY_CURRENT_USER, path, writable=True)
        winreg.DeleteValue(k, tip)
        winreg.CloseKey(k)
        results.append(f"已从启用列表移除: {tip}")
    except OSError as e:
        return {"ok": False, "message": f"移除失败: {e}"}

    # 清理 CTF SortOrder
    parsed = _parse_tip(tip)
    if parsed:
        lcid, clsid, profile = parsed
        try:
            lcid_hex = f"0x{int(lcid, 16):08X}"
        except (ValueError, TypeError):
            lcid_hex = None
        if lcid_hex:
            base = f"{CTF_SORT_BASE}\\{lcid_hex}\\{CTF_IME_CATEGORY}"
            for sub in _enum_subkeys(winreg.HKEY_CURRENT_USER, base):
                for n, v, _ in _enum_values(winreg.HKEY_CURRENT_USER, base + "\\" + sub):
                    pass
                data = dict((n, v) for n, v, _ in _enum_values(winreg.HKEY_CURRENT_USER, base + "\\" + sub))
                if str(data.get("CLSID", "")).lower() == clsid.lower() and \
                   str(data.get("Profile", "")).lower() == profile.lower():
                    try:
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + "\\" + sub)
                        results.append(f"已清理 CTF 排序条目: {sub}")
                    except OSError:
                        pass

    # 删除的是默认 → 清空 override
    if get_default_override() == tip:
        try:
            k = _open_key(winreg.HKEY_CURRENT_USER, PROFILE_KEY, writable=True)
            winreg.DeleteValue(k, "InputMethodOverride")
            winreg.CloseKey(k)
            results.append("已清空默认输入法设置")
        except OSError:
            pass

    # 重排剩余
    imes = get_imes(lang)
    if imes:
        tips = [it["tip"] for it in imes]
        r = apply_order(tips, lang)
        results.extend(r["results"])

    _notify_ctf()
    return {"ok": True, "message": "输入法已从启用列表移除（可重新启用）", "results": results}


def _is_cn_relevant(lp_lcid, tip_desc, name):
    """判断未启用的输入法是否与简体中文相关（用于显示过滤）。

    仅保留 0804(简体中文) 语言子键的输入法；已知中文输入法名称/描述直接放行，
    避免误杀 0804 之外但属中文场景的第三方 TSF。
    """
    try:
        lc = str(lp_lcid or "").lower()
        if lc in ("0x00000804", "804", "0804"):
            return True
    except (ValueError, TypeError):
        pass
    probe = ((tip_desc or "") + " " + (name or "")).lower()
    cn_kws = ("拼音", "输入法", "pinyin", "chinese", "zh-hans", "简体", "ime", "wetype", "qianwen", "doubao")
    return any(k in probe for k in cn_kws)


def _infer_profile(clsid, lcid="0x00000804"):
    """从 HKLM TIP LanguageProfile 推断某输入法的 profile GUID。

    优先返回与 lcid 匹配的语言子键下的第一个 profile；无法匹配时返回任意 profile。
    """
    try:
        want = f"{int(lcid, 16):08X}".lower()
    except (ValueError, TypeError):
        want = "00000804"
    base = TIP_HKLM + "\\" + clsid + r"\LanguageProfile"
    fallback = None
    try:
        for lg in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
            if fallback is None:
                fallback = lg
            if str(lg).lower() == want:
                for p in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base + "\\" + lg):
                    return p
    except OSError:
        pass
    if fallback:
        try:
            for p in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base + "\\" + fallback):
                return p
        except OSError:
            pass
    return ""


@acl_guard
def enable_ime(clsid, profile, lcid="0x00000804", lang=None):
    """重新启用输入法：追加到 User Profile 尾部 + CTF SortOrder 尾部。"""
    if lang is None:
        langs = list_languages()
        lang = langs[0] if langs else "zh-Hans-CN"
    if not profile:
        # 自动从 HKLM TIP LanguageProfile 推断（优先匹配 lcid）
        profile = _infer_profile(clsid, lcid)
    if not profile:
        return {"ok": False, "message": "无法确定该输入法的 profile，启用失败"}
    try:
        lcid_disp = f"{int(lcid, 16):04X}"
    except (ValueError, TypeError):
        lcid_disp = "0804"
    tip = f"{lcid_disp}:{clsid}{profile}"

    imes = get_imes(lang)
    tips = [it["tip"] for it in imes]
    if tip in tips:
        return {"ok": False, "message": "该输入法已在启用列表中"}

    tips.append(tip)
    path = PROFILE_KEY + "\\" + lang
    try:
        k = _open_key(winreg.HKEY_CURRENT_USER, path, writable=True)
        winreg.SetValueEx(k, tip, 0, winreg.REG_DWORD, len(tips))
        winreg.CloseKey(k)
    except OSError as e:
        return {"ok": False, "message": f"写入失败: {e}"}

    _write_ctf_order(lcid_disp, tips)
    _notify_ctf()
    return {"ok": True, "message": f"已启用「{_name_of(tip, lang)}」", "results": []}


# ---------------------------------------------------------------- 停用保留（开关联动）

def _load_disabled():
    """读取停用集合（已从启用列表移除但保留在 UI 的输入法 tip 列表）。"""
    if not os.path.exists(DISABLED_FILE):
        return []
    try:
        with open(DISABLED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save_disabled(tips):
    try:
        with open(DISABLED_FILE, "w", encoding="utf-8") as f:
            json.dump(tips, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def get_disabled():
    """返回停用集合（tip 列表）。"""
    return _load_disabled()


def _find_installed_by_tip(tip):
    """在已安装扫描结果中按 tip 匹配输入法注册信息。"""
    target = str(tip).lower()
    for it in scan_installed_imes():
        if it.get("tip") and str(it["tip"]).lower() == target:
            return it
    # 兜底：仅按 CLSID 匹配
    parsed = _parse_tip(tip)
    if parsed:
        _, clsid, _ = parsed
        for it in scan_installed_imes():
            if str(it.get("clsid", "")).lower() == clsid.lower():
                return it
    return None


def toggle_ime(tip, lang=None):
    """开关输入法：启用列表中→停用（移除但保留记录）；停用中→重新启用。"""
    if lang is None:
        langs = list_languages()
        lang = langs[0] if langs else "zh-Hans-CN"
    disabled = _load_disabled()
    imes = get_imes(lang)
    tips = [it["tip"] for it in imes]

    if tip in tips:
        # 关闭：从系统启用列表移除，记录停用（条目保留在 UI 并变暗）
        r = remove_ime(tip, lang)
        if not r.get("ok"):
            return r
        if tip not in disabled:
            disabled.append(tip)
            _save_disabled(disabled)
        return {"ok": True, "message": f"已停用「{_name_of(tip, lang)}」，可在列表中重新打开"}

    # 打开：重新启用，并清除停用记录
    inst = _find_installed_by_tip(tip)
    if not inst:
        return {"ok": False, "message": "未找到该输入法的注册信息，无法启用"}
    r = enable_ime(inst["clsid"], inst.get("profile", ""), "0x00000804", lang)
    if not r.get("ok"):
        return r
    if tip in disabled:
        disabled.remove(tip)
        _save_disabled(disabled)
    return {"ok": True, "message": f"已重新启用「{_name_of(tip, lang)}」"}


def remove_disabled(tip):
    """彻底移除停用记录（从 UI 列表删除，不再展示）。"""
    disabled = _load_disabled()
    if tip in disabled:
        disabled.remove(tip)
        _save_disabled(disabled)
    return {"ok": True, "message": "已从列表移除"}


# ---------------------------------------------------------------- 锁定与守护

def _notify_ctf():
    """通知输入法框架重载（重启 ctfmon 会闪烁输入法状态栏，故仅作尽力而为）。"""
    # 输入法顺序变更通常即时生效；此处不做强制重启，避免打扰用户。
    pass


def lock_order(lang=None):
    """锁定当前顺序：ACL 固化拒绝第三方写入 + 快照 watchdog 兜底。"""
    if lang is None:
        langs = list_languages()
        lang = langs[0] if langs else "zh-Hans-CN"
    imes = get_imes(lang)
    tips = [it["tip"] for it in imes]
    data = {
        "lang": lang,
        "tips": tips,
        "default": get_default_override(),
        "names": {it["tip"]: it["name"] for it in imes},
        "locked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        with open(LOCK_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return {"ok": False, "message": f"保存锁定快照失败: {e}"}

    acl_r = lock_acls()
    _lock_state["locked"] = True
    _lock_state["stop"] = False
    _lock_state["lang"] = lang
    if not _lock_state["thread"] or not _lock_state["thread"].is_alive():
        t = threading.Thread(target=_watchdog_loop, daemon=True)
        _lock_state["thread"] = t
        t.start()
    return {"ok": True, "acl": acl_r,
            "message": f"顺序已锁定（ACL 固化 + 守护，{len(tips)} 个输入法）"}


def unlock_order():
    """解除锁定：移除 ACL 固化并停止 watchdog。"""
    _lock_state["stop"] = True
    _lock_state["locked"] = False
    acl_r = unlock_acls()
    return {"ok": True, "acl": acl_r, "message": "已解除顺序锁定"}


def is_locked():
    return {
        "locked": _lock_state["locked"],
        "lock_file": os.path.exists(LOCK_FILE),
        "interval": WATCHDOG_INTERVAL,
        "acl": acl_status(),
    }


def _watchdog_loop():
    """后台守护线程：周期对比当前顺序与锁定快照，被篡改时自动恢复。"""
    while not _lock_state["stop"]:
        try:
            snap = load_lock()
            if snap and _lock_state["locked"]:
                _auto_restore_if_needed(snap)
        except Exception:
            pass
        time.sleep(WATCHDOG_INTERVAL)


def load_lock():
    if not os.path.exists(LOCK_FILE):
        return None
    try:
        with open(LOCK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _auto_restore_if_needed(snap):
    lang = snap.get("lang", "zh-Hans-CN")
    current = [it["tip"] for it in get_imes(lang)]
    expected = snap.get("tips", [])
    if not expected:
        return

    changed = False
    # 1) 原有输入法顺序被篡改（乱序 / 缺失）→ 恢复
    if current != expected:
        changed = True
        # 按锁定顺序重排（保留新增项在尾部）
        restored = list(expected)
        for t in current:
            if t not in restored:
                restored.append(t)
        apply_order(restored, lang)

    # 2) 默认输入法被改 → 恢复
    if snap.get("default"):
        if get_default_override() != snap["default"]:
            try:
                set_default(snap["default"], lang)
                changed = True
            except OSError:
                pass

    if changed:
        _log_watchdog("检测到输入法顺序被篡改，已自动恢复锁定顺序")


def _log_watchdog(msg):
    try:
        with open(WATCHDOG_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass


def diff_lock():
    """对比当前顺序与锁定快照。"""
    snap = load_lock()
    if not snap:
        return None
    lang = snap.get("lang", "zh-Hans-CN")
    current = [it["tip"] for it in get_imes(lang)]
    expected = snap.get("tips", [])
    return {
        "locked": _lock_state["locked"],
        "changed": current != expected,
        "current": current,
        "expected": expected,
        "new_items": [t for t in current if t not in expected],
        "missing": [t for t in expected if t not in current],
        "names": snap.get("names", {}),
        "default": snap.get("default"),
    }


def get_watchdog_log():
    if not os.path.exists(WATCHDOG_LOG):
        return []
    try:
        with open(WATCHDOG_LOG, "r", encoding="utf-8") as f:
            return [l.strip() for l in f.readlines() if l.strip()][-50:]
    except OSError:
        return []


# ---------------------------------------------------------------- 自检

if __name__ == "__main__":
    print("=== 已安装输入法（HKLM TIP 扫描） ===")
    for it in scan_installed_imes():
        print(f"  {it['name']:<12} enable={it['lp_enable']} in_use={it['in_use']}  {it['clsid']}")
    print("\n=== 当前启用输入法 ===")
    for it in get_imes():
        mark = "★默认" if it["is_default"] else ""
        print(f"  #{it['order']} {it['name']:<12} {mark}")
    print("\n=== 锁定状态 ===")
    print(" ", is_locked())
