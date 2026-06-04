# -*- coding: utf-8 -*-
# =============================================================================
#  【安全声明】本文件为校园跑（成都理工大学体育打卡小程序）安全漏洞的概念验证
#  （PoC）代码，仅用于安全研究、学习交流与向校方上报漏洞之目的。
#  严禁用于任何非法用途或真实的成绩作弊；由此产生的一切后果与作者本人无关。
#  详见仓库根目录 安全声明.md。
# =============================================================================
"""
从当前登录的微信小程序进程内存里自动提取并校验 clty.cdut.edu.cn 所需的 au token。

用法：
  py -3.12 auto_au.py
  py -3.12 auto_au.py --json

前提：微信电脑版里已经打开过目标小程序，并至少进入过会触发登录/规则请求的页面。
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import requests
except Exception as exc:  # pragma: no cover
    print(f"[!] 缺少 requests: {exc}", file=sys.stderr)
    raise


APPID = "wxff78672273295137"
BASE = os.environ.get("CDUT_BASE", "https://clty.cdut.edu.cn").rstrip("/")
ROOT = Path(__file__).resolve().parent
CACHE_PATH = ROOT / "au_token_cache.json"

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
SIZE_T = ctypes.c_size_t


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wt.LPVOID),
        ("AllocationBase", wt.LPVOID),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", SIZE_T),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wt.HANDLE, wt.LPCVOID, ctypes.POINTER(MBI), SIZE_T]
VirtualQueryEx.restype = SIZE_T

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
ReadProcessMemory.restype = wt.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype = wt.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
CreateToolhelp32Snapshot.restype = wt.HANDLE

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wt.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wt.BOOL


TOKEN_RE = re.compile(r'"au"\s*:\s*"([A-Za-z0-9+/=]{24,512})"')
FIELD_STR_RE = {
    k: re.compile(rf'"{re.escape(k)}"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', re.S)
    for k in ("userCode", "userName", "classCode", "openId", "sessionKey", "phone")
}
FIELD_NUM_RE = {
    k: re.compile(rf'"{re.escape(k)}"\s*:\s*(-?\d+)', re.S)
    for k in ("userId", "userType", "sex")
}


@dataclass
class Candidate:
    au: str
    pid: int
    source: str
    score: int
    userInfo: Dict[str, Any]
    contextHint: str = ""


def _err() -> int:
    return ctypes.get_last_error()


def enum_processes(names: Tuple[str, ...] = ("WeChatAppEx.exe",)) -> List[Tuple[int, str]]:
    want = {n.lower() for n in names}
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise OSError(f"CreateToolhelp32Snapshot failed: {_err()}")
    out: List[Tuple[int, str]] = []
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            exe = pe.szExeFile
            if exe.lower() in want:
                out.append((int(pe.th32ProcessID), exe))
            ok = Process32NextW(snap, ctypes.byref(pe))
    finally:
        CloseHandle(snap)
    return out


def mini_headers(au: str) -> Dict[str, str]:
    # 尽量贴近微信 Windows 小程序的 wx.request 请求头；au 是服务端真正校验的会话字段。
    return {
        "au": au,
        "Accept": "*/*",
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "MicroMessenger/3.9.12.17(0x63090c11) "
            "WindowsWechat(0x63090c11) XWEB/12757"
        ),
        "Referer": f"https://servicewechat.com/{APPID}/20/page-frame.html",
        "xweb_xhr": "1",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }


def _decode_string_value(s: str) -> str:
    try:
        return json.loads('"' + s + '"')
    except Exception:
        return s


def _flatten_user_fields(obj: Any) -> Dict[str, Any]:
    wanted = {"userId", "userCode", "userType", "userName", "classCode", "openId", "sessionKey", "phone", "sex"}
    info: Dict[str, Any] = {}

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k in wanted and k not in info:
                    info[k] = v
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    walk(obj)
    return info


def _parse_flat_fields(ctx: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    for key, rx in FIELD_STR_RE.items():
        m = rx.search(ctx)
        if m:
            info[key] = _decode_string_value(m.group(1))
    for key, rx in FIELD_NUM_RE.items():
        m = rx.search(ctx)
        if m:
            try:
                info[key] = int(m.group(1))
            except Exception:
                pass
    return info


def _brace_end(text: str, start: int, max_len: int = 12000) -> int:
    depth = 0
    in_str = False
    esc = False
    limit = min(len(text), start + max_len)
    for i in range(start, limit):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _json_objects_around(ctx: str, anchor: int) -> Iterator[Dict[str, Any]]:
    left = max(0, anchor - 3500)
    starts = [m.start() for m in re.finditer(r"\{", ctx[left : anchor + 1])]
    for rel_start in reversed(starts[-80:]):
        st = left + rel_start
        ed = _brace_end(ctx, st)
        if ed < 0 or ed < anchor:
            continue
        raw = ctx[st : ed + 1]
        if '"au"' not in raw:
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        yield obj


def _score(info: Dict[str, Any], ctx: str) -> int:
    score = 0
    if info.get("userCode"):
        score += 45
    if info.get("userType") == 1:
        score += 35
    elif "userType" in info:
        score += 15
    if info.get("userName"):
        score += 20
    if info.get("classCode"):
        score += 10
    if info.get("sessionKey"):
        score += 8
    if "check/rules" in ctx or "soprt" in ctx or "sport" in ctx:
        score += 8
    if "clty.cdut.edu.cn" in ctx:
        score += 8
    return score


def extract_candidates_from_text(text: str, pid: int, source: str) -> Iterator[Candidate]:
    if '"au"' not in text:
        return
    for m in TOKEN_RE.finditer(text):
        au = m.group(1)
        if len(au) < 32:
            continue
        c0 = max(0, m.start() - 4500)
        c1 = min(len(text), m.end() + 7000)
        ctx = text[c0:c1]
        anchor = m.start() - c0
        infos: List[Dict[str, Any]] = []
        for obj in _json_objects_around(ctx, anchor):
            info = _flatten_user_fields(obj)
            if info:
                infos.append(info)
        if not infos:
            infos.append(_parse_flat_fields(ctx))
        for info in infos:
            hint_bits = []
            for key in ("userId", "userCode", "userType", "userName", "classCode"):
                if key in info:
                    hint_bits.append(f"{key}={info[key]}")
            yield Candidate(
                au=au,
                pid=pid,
                source=source,
                score=_score(info, ctx),
                userInfo=info,
                contextHint=", ".join(hint_bits),
            )


def _readable_region(protect: int) -> bool:
    if protect & PAGE_NOACCESS:
        return False
    if protect & PAGE_GUARD:
        return False
    return True


def scan_process(pid: int, *, max_candidates: int = 200, verbose: bool = False) -> List[Candidate]:
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        if verbose:
            print(f"[-] OpenProcess({pid}) failed: {_err()}", file=sys.stderr)
        return []

    out: List[Candidate] = []
    seen: Dict[str, Candidate] = {}
    mbi = MBI()
    addr = 0
    chunk_size = 4 * 1024 * 1024
    overlap = 64 * 1024
    ascii_pat = b'"au"'
    utf16_pat = '"au"'.encode("utf-16le")

    try:
        while addr < (1 << 47):
            q = VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not q:
                break
            base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
            size = int(mbi.RegionSize)
            protect = int(mbi.Protect)
            if size <= 0:
                addr += 0x1000
                continue

            if mbi.State == MEM_COMMIT and _readable_region(protect):
                off = 0
                while off < size:
                    n = min(chunk_size, size - off)
                    buf = ctypes.create_string_buffer(n)
                    br = SIZE_T()
                    ok = ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(br))
                    if ok and br.value:
                        data = buf.raw[: br.value]
                        if ascii_pat in data:
                            text = data.decode("utf-8", "ignore")
                            for cand in extract_candidates_from_text(text, pid, f"pid:{pid}:ascii"):
                                old = seen.get(cand.au)
                                if old is None or cand.score > old.score:
                                    seen[cand.au] = cand
                        if utf16_pat in data:
                            # 忽略半个 wchar 的对齐问题：真实 JSON 字段足够长，下一块 overlap 会兜底。
                            text = data.decode("utf-16le", "ignore")
                            for cand in extract_candidates_from_text(text, pid, f"pid:{pid}:utf16le"):
                                old = seen.get(cand.au)
                                if old is None or cand.score > old.score:
                                    seen[cand.au] = cand
                        if len(seen) >= max_candidates:
                            break
                    off += max(1, chunk_size - overlap)
                if len(seen) >= max_candidates:
                    break
            addr = base + size
    finally:
        CloseHandle(h)

    out = sorted(seen.values(), key=lambda c: c.score, reverse=True)
    if verbose:
        print(f"[+] pid={pid} candidates={len(out)}", file=sys.stderr)
    return out


def scan_all(*, max_candidates: int = 300, verbose: bool = False) -> List[Candidate]:
    procs = enum_processes()
    if verbose:
        print(f"[*] WeChatAppEx processes: {procs}", file=sys.stderr)
    merged: Dict[str, Candidate] = {}
    for pid, exe in procs:
        for cand in scan_process(pid, max_candidates=max_candidates, verbose=verbose):
            old = merged.get(cand.au)
            if old is None or cand.score > old.score:
                merged[cand.au] = cand
    return sorted(merged.values(), key=lambda c: c.score, reverse=True)


def validate_au(au: str, *, base: str = BASE, timeout: float = 10.0) -> Dict[str, Any]:
    sess = requests.Session()
    sess.headers.update(mini_headers(au))
    url = base + "/api/applet/soprt/user/check/rules"
    try:
        r = sess.post(url, data=b"{}", timeout=timeout)
        text = r.text
        try:
            j = r.json()
        except Exception:
            return {"ok": False, "http": r.status_code, "error": text[:300]}
    except Exception as exc:
        return {"ok": False, "error": repr(exc)}

    ok = r.status_code == 200 and j.get("code") == 0 and isinstance(j.get("data"), dict)
    result = {
        "ok": bool(ok),
        "http": r.status_code,
        "code": j.get("code"),
        "msg": j.get("msg"),
    }
    if ok:
        bean = (j.get("data") or {}).get("bean") or {}
        result["rules"] = {
            k: bean.get(k)
            for k in ("type", "milage", "timeRule", "speedRule", "limitTime", "placeId", "soprtName")
            if k in bean
        }
    return result


def _mask_token(au: str) -> str:
    if len(au) <= 14:
        return au[:3] + "***"
    return au[:8] + "..." + au[-6:]


def _read_cache() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_cache(data: Dict[str, Any]) -> None:
    safe = dict(data)
    safe["cachedAt"] = time.strftime("%Y-%m-%d %H:%M:%S")
    CACHE_PATH.write_text(json.dumps(safe, ensure_ascii=False, indent=2), encoding="utf-8")


def get_valid_au(
    *,
    base: str = BASE,
    prefer_cache: bool = False,
    validate: bool = True,
    verbose: bool = False,
) -> Dict[str, Any]:
    if prefer_cache:
        cached = _read_cache()
        if cached and cached.get("au"):
            val = validate_au(cached["au"], base=base) if validate else {"ok": True, "cached": True}
            if val.get("ok"):
                cached["validation"] = val
                if verbose:
                    print(f"[+] cache valid: {_mask_token(cached['au'])}", file=sys.stderr)
                return cached

    candidates = scan_all(verbose=verbose)
    if not candidates:
        raise RuntimeError("没有在 WeChatAppEx.exe 内存里找到 au；请先打开目标小程序并进入一次运动/规则页面。")

    tried = set()
    last_errors: List[Dict[str, Any]] = []
    for cand in candidates:
        if cand.au in tried:
            continue
        tried.add(cand.au)
        if verbose:
            print(f"[*] try au={_mask_token(cand.au)} score={cand.score} {cand.contextHint}", file=sys.stderr)
        val = validate_au(cand.au, base=base) if validate else {"ok": True, "skipped": True}
        if val.get("ok"):
            data = {
                "au": cand.au,
                "userInfo": cand.userInfo,
                "pid": cand.pid,
                "source": cand.source,
                "score": cand.score,
                "validation": val,
            }
            _write_cache(data)
            return data
        last_errors.append({"au": _mask_token(cand.au), "score": cand.score, "validation": val})

    raise RuntimeError("找到了 au 候选但都未通过规则接口校验：" + json.dumps(last_errors[:8], ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="只输出机器可读 JSON")
    ap.add_argument("--cache-first", action="store_true", help="优先使用已缓存且仍有效的 au")
    ap.add_argument("--no-validate", action="store_true", help="只提取不访问规则接口校验")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    try:
        data = get_valid_au(prefer_cache=args.cache_first, validate=not args.no_validate, verbose=args.verbose)
    except Exception as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"ok": True, **data}, ensure_ascii=False))
    else:
        print("[+] au 获取并校验成功")
        print(f"    token: {_mask_token(data['au'])}")
        if data.get("userInfo"):
            print("    user:", json.dumps(data["userInfo"], ensure_ascii=False))
        if data.get("validation", {}).get("rules"):
            print("    rules:", json.dumps(data["validation"]["rules"], ensure_ascii=False))
        print(f"    cache: {CACHE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

