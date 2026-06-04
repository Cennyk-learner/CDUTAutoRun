# 【安全声明】微信小程序进程内存扫描脚本（定位用户字段/规则痕迹），仅用于安全研究与
# 学习交流，严禁用于窃取他人凭证或任何非法用途；后果与作者本人无关。详见 安全声明.md。
import ctypes, ctypes.wintypes as wt, sys, re
PROCESS_QUERY_INFORMATION=0x0400; PROCESS_VM_READ=0x0010; MEM_COMMIT=0x1000; PAGE_NOACCESS=0x01; PAGE_GUARD=0x100
kernel=ctypes.WinDLL('kernel32', use_last_error=True); SIZE_T=ctypes.c_size_t
class MBI(ctypes.Structure): _fields_=[('BaseAddress', wt.LPVOID),('AllocationBase', wt.LPVOID),('AllocationProtect', wt.DWORD),('RegionSize', SIZE_T),('State', wt.DWORD),('Protect', wt.DWORD),('Type', wt.DWORD)]
VirtualQueryEx=kernel.VirtualQueryEx; VirtualQueryEx.argtypes=[wt.HANDLE, wt.LPCVOID, ctypes.POINTER(MBI), SIZE_T]; VirtualQueryEx.restype=SIZE_T
ReadProcessMemory=kernel.ReadProcessMemory; ReadProcessMemory.argtypes=[wt.HANDLE, wt.LPCVOID, wt.LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]; ReadProcessMemory.restype=wt.BOOL
OpenProcess=kernel.OpenProcess; OpenProcess.argtypes=[wt.DWORD, wt.BOOL, wt.DWORD]; OpenProcess.restype=wt.HANDLE
CloseHandle=kernel.CloseHandle
patterns=[b'"au"', b'"au":', b'"userType"', b'"openId"', b'"stu', b'"student', b'"teacher', b'wxCode', b'check/rules', b'completeNum', b'cycleCount', b'timeRule', b'milage', b'lineGps']
patterns_u=[p.decode('latin1').encode('utf-16le') for p in patterns]
def asc(bs): return ''.join(chr(c) if 32<=c<127 else '\n' if c in (10,13) else '.' for c in bs)
def scan(pid, max_hits=200):
 h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, False, pid); print('PID',pid,'handle',h); hits=0
 if not h: return
 mbi=MBI(); addr=0
 try:
  while addr < (1<<47):
   if not VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)): break
   base=ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0; size=int(mbi.RegionSize); prot=int(mbi.Protect)
   if mbi.State==MEM_COMMIT and not(prot&PAGE_NOACCESS) and not(prot&PAGE_GUARD) and size>0:
    off=0; cs=4*1024*1024; ov=4096
    while off<size:
     n=min(cs,size-off); buf=ctypes.create_string_buffer(n); br=SIZE_T()
     if ReadProcessMemory(h, ctypes.c_void_p(base+off), buf, n, ctypes.byref(br)) and br.value:
      data=buf.raw[:br.value]
      for pat in patterns:
       st=0
       while True:
        i=data.find(pat,st)
        if i<0: break
        ctx=data[max(0,i-260):min(len(data),i+1100)]
        print('\n-- ascii',pat,'@',hex(base+off+i)); print(asc(ctx)[:2200]); hits+=1; st=i+1
        if hits>=max_hits: return
      for patu,orig in zip(patterns_u,patterns):
       st=0
       while True:
        i=data.find(patu,st)
        if i<0: break
        ctx=data[max(0,i-260):min(len(data),i+1100)]
        print('\n-- utf16',orig,'@',hex(base+off+i)); print(ctx.decode('utf-16le','replace')[:1600].encode('utf-8','replace').decode('utf-8','replace')); hits+=1; st=i+2
        if hits>=max_hits: return
     off += max(1, cs-ov)
   addr=base+size
 finally: CloseHandle(h)
 print('hits',hits)
for p in map(int, sys.argv[1:]): scan(p)
