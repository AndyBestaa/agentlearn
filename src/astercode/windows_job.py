"""Windows Job Object resource and process-tree containment primitives.

This module deliberately does *not* describe a Job Object as a filesystem or
network sandbox.  It enforces only the limits configured below and keeps the
job handle alive so ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` remains effective.
"""

from __future__ import annotations

import ctypes
import math
import os
import time
from ctypes import wintypes
from dataclasses import dataclass

CREATE_SUSPENDED = 0x00000004

JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS = 1
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9

PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPTHREAD = 0x00000004
HANDLE_FLAG_INHERIT = 0x00000001
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class WindowsJobError(RuntimeError):
    """Raised when a required Job Object boundary cannot be established."""


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_int64),
        ("TotalKernelTime", ctypes.c_int64),
        ("ThisPeriodTotalUserTime", ctypes.c_int64),
        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class WindowsJobLimits:
    """Limits enforced for one process tree."""

    active_process_limit: int
    job_memory_limit: int | None = None
    job_cpu_time_limit_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.active_process_limit < 1 or self.active_process_limit > 1_024:
            raise ValueError("active_process_limit must be between 1 and 1024")
        if self.job_memory_limit is not None and self.job_memory_limit < 16_777_216:
            raise ValueError("job_memory_limit must be at least 16 MiB")
        if self.job_cpu_time_limit_seconds is not None and (
            not math.isfinite(self.job_cpu_time_limit_seconds)
            or self.job_cpu_time_limit_seconds < 0.01
            or self.job_cpu_time_limit_seconds > 604_800
        ):
            raise ValueError(
                "job_cpu_time_limit_seconds must be finite and between 0.01 and 604800"
            )


def _raise_last_error(operation: str) -> None:
    code = ctypes.get_last_error()
    raise WindowsJobError(f"{operation} failed with Windows error {code}")


def _kernel32() -> ctypes.WinDLL:  # type: ignore[name-defined]
    if os.name != "nt":
        raise WindowsJobError("Windows Job Objects are available only on Windows")
    return ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,no-any-return]


class WindowsJobObject:
    """Own an unnamed Job Object and its kill-on-close lifetime boundary."""

    def __init__(self, limits: WindowsJobLimits) -> None:
        if os.name != "nt":
            raise WindowsJobError("Windows Job Objects are available only on Windows")
        self.limits = limits
        self._api = _kernel32()
        self._bind_api()
        handle = self._api.CreateJobObjectW(None, None)
        if not handle:
            _raise_last_error("CreateJobObjectW")
        self._handle: int | None = int(handle)
        try:
            # SECURITY_ATTRIBUTES is null, so this is already non-inheritable;
            # enforce the property explicitly to guard future refactors.
            if not self._api.SetHandleInformation(
                wintypes.HANDLE(self._handle), HANDLE_FLAG_INHERIT, 0
            ):
                _raise_last_error("SetHandleInformation(job)")
            self._set_limits()
        except Exception:
            self.close()
            raise

    def _bind_api(self) -> None:
        api = self._api
        api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        api.CreateJobObjectW.restype = wintypes.HANDLE
        api.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
        api.SetHandleInformation.restype = wintypes.BOOL
        api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        api.SetInformationJobObject.restype = wintypes.BOOL
        api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        api.AssignProcessToJobObject.restype = wintypes.BOOL
        api.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        api.QueryInformationJobObject.restype = wintypes.BOOL
        api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        api.TerminateJobObject.restype = wintypes.BOOL
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        api.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
        api.Thread32First.restype = wintypes.BOOL
        api.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
        api.Thread32Next.restype = wintypes.BOOL
        api.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenThread.restype = wintypes.HANDLE
        api.ResumeThread.argtypes = [wintypes.HANDLE]
        api.ResumeThread.restype = wintypes.DWORD
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL

    @property
    def closed(self) -> bool:
        return self._handle is None

    @property
    def limit_flags(self) -> int:
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        if self.limits.job_memory_limit is not None:
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
        if self.limits.job_cpu_time_limit_seconds is not None:
            flags |= JOB_OBJECT_LIMIT_JOB_TIME
        return flags

    def _job_handle(self) -> wintypes.HANDLE:
        if self._handle is None:
            raise WindowsJobError("Job Object handle is closed")
        return wintypes.HANDLE(self._handle)

    def _set_limits(self) -> None:
        information = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        information.BasicLimitInformation.LimitFlags = self.limit_flags
        information.BasicLimitInformation.ActiveProcessLimit = self.limits.active_process_limit
        if self.limits.job_cpu_time_limit_seconds is not None:
            # Windows represents job user-mode CPU time in 100 ns ticks.
            information.BasicLimitInformation.PerJobUserTimeLimit = max(
                1, int(self.limits.job_cpu_time_limit_seconds * 10_000_000)
            )
        if self.limits.job_memory_limit is not None:
            information.JobMemoryLimit = self.limits.job_memory_limit
        if not self._api.SetInformationJobObject(
            self._job_handle(),
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            _raise_last_error("SetInformationJobObject")

    def assign_suspended_process(self, pid: int) -> None:
        """Assign a process that the caller created with ``CREATE_SUSPENDED``."""

        if pid <= 0:
            raise ValueError("pid must be positive")
        process = self._api.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        if not process:
            _raise_last_error("OpenProcess(assign)")
        try:
            if not self._api.AssignProcessToJobObject(self._job_handle(), process):
                # This also covers an incompatible parent/nested-job policy.
                _raise_last_error("AssignProcessToJobObject")
        finally:
            self._api.CloseHandle(process)

    def _thread_ids(self, pid: int) -> list[int]:
        snapshot = self._api.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if not snapshot or int(snapshot) == INVALID_HANDLE_VALUE:
            _raise_last_error("CreateToolhelp32Snapshot")
        ids: list[int] = []
        entry = _THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        try:
            if self._api.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if int(entry.th32OwnerProcessID) == pid:
                        ids.append(int(entry.th32ThreadID))
                    entry.dwSize = ctypes.sizeof(entry)
                    if not self._api.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._api.CloseHandle(snapshot)
        return ids

    def resume_suspended_process(self, pid: int) -> None:
        """Resume the unique primary thread of a newly suspended process."""

        thread_ids = self._thread_ids(pid)
        if len(thread_ids) != 1:
            raise WindowsJobError(
                f"suspended process must have exactly one thread before resume; observed {len(thread_ids)}"
            )
        thread = self._api.OpenThread(THREAD_SUSPEND_RESUME, False, thread_ids[0])
        if not thread:
            _raise_last_error("OpenThread(resume)")
        try:
            previous_count = int(self._api.ResumeThread(thread))
            if previous_count == 0xFFFFFFFF:
                _raise_last_error("ResumeThread")
            if previous_count != 1:
                raise WindowsJobError(
                    f"unexpected primary-thread suspend count {previous_count}; refusing launch"
                )
        finally:
            self._api.CloseHandle(thread)

    def assign_and_resume(self, pid: int) -> None:
        """Establish limits before allowing any target code to execute."""

        self.assign_suspended_process(pid)
        try:
            self.resume_suspended_process(pid)
        except Exception:
            # Assignment already succeeded, so the Job is the authoritative
            # full-tree cleanup boundary even if resuming failed.
            self.terminate(timeout=1.0)
            raise

    def active_process_count(self) -> int:
        information = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        returned = wintypes.DWORD()
        if not self._api.QueryInformationJobObject(
            self._job_handle(),
            JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
            ctypes.byref(returned),
        ):
            _raise_last_error("QueryInformationJobObject")
        return int(information.ActiveProcesses)

    def terminate(self, *, exit_code: int = 1, timeout: float = 3.0) -> bool:
        """Terminate every process in the Job and confirm its active count is zero."""

        if self.closed:
            return False
        if not self._api.TerminateJobObject(self._job_handle(), exit_code):
            _raise_last_error("TerminateJobObject")
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.active_process_count() == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)

    def close(self) -> None:
        """Close the non-inheritable handle; kill-on-close applies to the tree."""

        handle, self._handle = self._handle, None
        if handle is not None:
            self._api.CloseHandle(wintypes.HANDLE(handle))

    def __enter__(self) -> WindowsJobObject:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Interpreter shutdown can tear down module globals in any order.
        try:
            self.close()
        except Exception:
            pass


__all__ = [
    "CREATE_SUSPENDED",
    "JOB_OBJECT_LIMIT_ACTIVE_PROCESS",
    "JOB_OBJECT_LIMIT_JOB_TIME",
    "JOB_OBJECT_LIMIT_JOB_MEMORY",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "WindowsJobError",
    "WindowsJobLimits",
    "WindowsJobObject",
]
