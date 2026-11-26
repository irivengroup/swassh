"""Documented Win32 primitives, loaded only on Windows (standard ctypes).

The guardian joins its own kill-on-close job BEFORE it creates any native
client. Children inherit job membership at creation, without an assignment race.
No breakaway flag is enabled; incompatible enclosing jobs fail closed.
"""
from __future__ import annotations
import ctypes
import os
from ctypes import wintypes


def kernel32():
    if os.name != 'nt':
        raise OSError('Win32 adapter is only available on Windows')
    return ctypes.WinDLL('kernel32', use_last_error=True)


def checked(value):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


class KillJob:
    def __init__(self):
        kernel = self.kernel = kernel32()
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                ('flags', wintypes.DWORD), ('minimum_working_set', ctypes.c_size_t),
                ('maximum_working_set', ctypes.c_size_t), ('active_process_limit', wintypes.DWORD),
                ('affinity', ctypes.c_size_t), ('priority_class', wintypes.DWORD),
                ('scheduling_class', wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('process_memory', ctypes.c_size_t),
                ('job_memory', ctypes.c_size_t), ('peak_process_memory', ctypes.c_size_t),
                ('peak_job_memory', ctypes.c_size_t)]
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = checked(kernel.CreateJobObjectW(None, None))
        try:
            limits = Extended()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            checked(kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            checked(kernel.AssignProcessToJobObject(self.handle, kernel.GetCurrentProcess()))
        except BaseException:
            kernel.CloseHandle(self.handle)
            raise
        # Intentionally retained until guardian process exit. Explicit CloseHandle
        # would terminate this guardian as well as every client in its job.

    def terminate(self, code):
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateJobObject.restype = wintypes.BOOL
        checked(self.kernel.TerminateJobObject(self.handle, code))
        os._exit(code)  # Defensive if termination is asynchronously delivered.


class ParentProcess:
    def __init__(self, pid, expected=None):
        kernel = self.kernel = kernel32()
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = checked(kernel.OpenProcess(0x100000 | 0x1000, False, pid))
        times = [wintypes.FILETIME() for _ in range(4)]
        try:
            checked(kernel.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times)))
            self.token = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            if expected is not None and self.token != expected:
                raise ValueError('guardian parent creation identity changed')
        except BaseException:
            self.close()
            raise

    def alive(self):
        state = self.kernel.WaitForSingleObject(self.handle, 0)
        if state == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        return state == 0x102

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class DirectoryHandle:
    """Exclude FILE_SHARE_DELETE to pin ancestry against renames and junction swaps."""

    # The native layout is immutable. Rebuilding a ctypes type for every
    # ancestor multiplies interpreter work while database writers hold locks.
    class _Information(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('creation', wintypes.FILETIME),
            ('access', wintypes.FILETIME), ('write', wintypes.FILETIME),
            ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
            ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
            ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]
    def __init__(self, path):
        kernel = self.kernel = kernel32()
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        # Metadata-only opens do not enforce all sharing constraints on Windows.
        # FILE_LIST_DIRECTORY makes denial of FILE_SHARE_DELETE effective.
        self.handle = kernel.CreateFileW(str(path), 0x81, 3, None, 3, 0x02000000 | 0x00200000, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = self._Information()
            checked(kernel.GetFileInformationByHandle(self.handle, ctypes.byref(info)))
            if not info.attributes & 0x10 or info.attributes & 0x400:
                raise ValueError('Windows output ancestor is not a plain directory')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def protect_directory(path):
    """Private Windows DACL, only for a directory owned by the current token."""
    kernel = kernel32()
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi.EqualSid.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    class SIDAttributes(ctypes.Structure):
        _fields_ = [('sid', ctypes.c_void_p), ('attributes', wintypes.DWORD)]
    token = wintypes.HANDLE()
    owner = ctypes.c_void_p()
    security = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    text_sid = wintypes.LPWSTR()
    try:
        checked(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        checked(advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)))
        sid = ctypes.cast(buffer, ctypes.POINTER(SIDAttributes)).contents.sid
        error = advapi.GetNamedSecurityInfoW(str(path), 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(security))
        if error:
            raise ctypes.WinError(error)
        if not advapi.EqualSid(owner, sid):
            raise ValueError('Windows private directory must belong to this account')
        checked(advapi.ConvertSidToStringSidW(sid, ctypes.byref(text_sid)))
        sddl = 'D:P(A;OICI;FA;;;' + text_sid.value + ')(A;OICI;FA;;;SY)'
        checked(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None))
        checked(advapi.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor))
    finally:
        for allocation in (security, descriptor, text_sid):
            if allocation:
                kernel.LocalFree(ctypes.cast(allocation, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def regular_file_size(path) -> int:
    """Inspect a live native writer without asking for file-data read access.

    GetFileInformationByHandle supplies the real link count (DirEntry.stat
    omits it on Windows). Open the entry itself, refuse directories/reparse
    points and non-disk handles, and always release this metadata-only handle.
    The caller retains its private pinned staging directory and performs final
    descriptor/hash verification after the native writer has closed.
    """
    kernel = kernel32()
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    class Information(ctypes.Structure):
        # Fixed-width DWORDs keep this documented 52-byte layout testable on
        # non-Windows hosts, whose native C unsigned long may be 64 bits.
        _fields_ = [('attributes', ctypes.c_uint32), ('times', ctypes.c_uint32 * 6),
            ('volume', ctypes.c_uint32), ('size_high', ctypes.c_uint32),
            ('size_low', ctypes.c_uint32), ('links', ctypes.c_uint32),
            ('index_high', ctypes.c_uint32), ('index_low', ctypes.c_uint32)]
    handle = kernel.CreateFileW(str(path), 0, 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = Information()
        checked(kernel.GetFileInformationByHandle(handle, ctypes.byref(info)))
        if kernel.GetFileType(handle) != 1 or info.attributes & 0x410 or info.links != 1:
            raise ValueError('download staging contains a link or special entry')
        return (info.size_high << 32) | info.size_low
    finally:
        kernel.CloseHandle(handle)


def open_file_without_reparse(path, flags, *, share_delete: bool = False):
    """Open a checked entry; atomic receipt readers may permit replacement.

    Delete sharing is opt-in. All existing callers keep their read/write sharing
    contract, access rights, reparse refusal and handle ownership.
    """
    import msvcrt
    kernel = kernel32()
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    access = 0x40000000 if flags & (os.O_WRONLY | os.O_RDWR) else 0x80000000
    if flags & os.O_RDWR:
        access |= 0x80000000
    disposition = 1 if flags & os.O_EXCL else 4 if flags & os.O_CREAT else 3
    sharing = 3 | (4 if share_delete else 0)
    handle = kernel.CreateFileW(str(path), access, sharing, None, disposition, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # BY_HANDLE_FILE_INFORMATION starts with attributes. Allocate its entire
        # documented 52-byte structure, not a DWORD-sized overflow-prone buffer.
        info = ctypes.create_string_buffer(52)
        checked(kernel.GetFileInformationByHandle(handle, info))
        attributes = ctypes.cast(info, ctypes.POINTER(wintypes.DWORD)).contents.value
        if attributes & (0x400 | 0x10):
            raise ValueError('Windows private file must not be a reparse point or directory')
        fd = msvcrt.open_osfhandle(handle, flags | os.O_BINARY)
        handle = None
        return fd
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)


def replace_atomic_receipt(source, destination):
    """Replace a private receipt while delete-sharing readers retain snapshots.

    MoveFileEx replacement rejects a live target even with delete sharing on
    supported Windows systems. ReplaceFileW preserves the existing attributes
    and ACLs; no ignore-error flag or retry is used. A missing destination is
    the initial publication and uses the original atomic move operation.
    """
    kernel = kernel32()
    kernel.ReplaceFileW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    kernel.ReplaceFileW.restype = wintypes.BOOL
    if kernel.ReplaceFileW(str(destination), str(source), None, 0, None, None):
        return
    error = ctypes.get_last_error()
    if error == 2:
        os.replace(source, destination)
    else:
        raise ctypes.WinError(error)
