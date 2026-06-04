# 【安全声明】微信小程序进程内存扫描脚本（定位接口/token 痕迹），仅用于安全研究与
# 学习交流，严禁用于窃取他人凭证或任何非法用途；后果与作者本人无关。详见 安全声明.md。
import ctypes, ctypes.wintypes as wt, sys, re, os, time
PROCESS_QUERY_INFORMATION=0x0400
PROCESS_VM_READ=0x0010
MEM_COMMIT=0x1000
PAGE_NOACCESS=0x01
PAGE_GUARD=0x100
kernel=ctypes.WinDLL('kernel32', use_last_error=True)
SIZE_T=ctypes.c_size_t
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_=[('BaseAddress', wt.LPVOID),('AllocationBase', wt.LPVOID),('AllocationProtect', wt.DWORD),('RegionSize', SIZE_T),('State', wt.DWORD),('Protect', wt.DWORD),('Type', wt.DWORD)]
VirtualQueryEx=kernel.VirtualQueryEx
VirtualQueryEx.argtypes=[wt.HANDLE, wt.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
VirtualQueryEx.restype=SIZE_T
ReadProcessMemory=kernel.ReadProcessMemory
ReadProcessMemory.argtypes=[wt.HANDLE, wt.LPCVOID, wt.LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
ReadProcessMemory.restype=wt.BOOL
OpenProcess=kernel.OpenProcess
OpenProcess.argtypes=[wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype=wt.HANDLE
CloseHandle=kernel.CloseHandle
patterns=[b'clty.cdut.edu.cn', b'/api/applet/soprt/start', b'/coll/collect/sport/gps', b'user_wx_token', b'/api/user/wx/login', b'/api/applet/soprt/user/check/rules', b'/api/applet/soprt/update/state', b'/api/applet/soprt/end', b'totalMilage']
patterns_u=[p.decode('latin1').encode('utf-16le') for p in patterns]

def safe_ascii(chunk):
    return ''.join(chr(c) if 32<=c<127 else '\n' if c in (10,13) else '.' for c in chunk)

def scan_pid(pid, max_hits=30):
    hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, False, pid)
    if not hp:
        print(f'[PID {pid}] OpenProcess failed {ctypes.get_last_error()}'); return
    print(f'\n[PID {pid}] scanning')
    mbi=MEMORY_BASIC_INFORMATION(); addr=0; hits=0; regions=0; readmb=0
    try:
        while addr < (1<<47):
            res=VirtualQueryEx(hp, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not res: break
            base=ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
            size=int(mbi.RegionSize)
            prot=int(mbi.Protect)
            if mbi.State==MEM_COMMIT and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD) and size>0:
                regions+=1
                # cap huge regions: read in chunks with overlap
                off=0; chunk_size=4*1024*1024; overlap=4096
                while off<size:
                    n=min(chunk_size, size-off)
                    buf=ctypes.create_string_buffer(n)
                    br=SIZE_T()
                    if ReadProcessMemory(hp, ctypes.c_void_p(base+off), buf, n, ctypes.byref(br)) and br.value:
                        data=buf.raw[:br.value]
                        readmb += br.value/1048576
                        for pat in patterns:
                            st=0
                            while True:
                                i=data.find(pat, st)
                                if i<0: break
                                absaddr=base+off+i
                                ctx=data[max(0,i-220):min(len(data),i+800)]
                                print(f'-- hit ascii {pat!r} @0x{absaddr:x}')
                                print(safe_ascii(ctx)[:1600])
                                hits+=1; st=i+1
                                if hits>=max_hits: return
                        for patu,orig in zip(patterns_u,patterns):
                            st=0
                            while True:
                                i=data.find(patu, st)
                                if i<0: break
                                absaddr=base+off+i
                                ctx=data[max(0,i-220):min(len(data),i+800)]
                                # decode utf16 view loosely
                                try: txt=ctx.decode('utf-16le','ignore')
                                except: txt=safe_ascii(ctx)
                                print(f'-- hit utf16 {orig!r} @0x{absaddr:x}')
                                print(txt[:1600])
                                hits+=1; st=i+2
                                if hits>=max_hits: return
                    off += max(1, chunk_size-overlap)
            addr=base+size
    finally:
        CloseHandle(hp)
    print(f'[PID {pid}] done hits={hits} regions={regions} readMB={readmb:.1f}')

if __name__=='__main__':
    for pid in map(int, sys.argv[1:]): scan_pid(pid)

