"""Reading the membership of a sandbox's Job Object.

Shared by the integration and system tests: both need to see which
processes a sandbox currently owns, which is how process-tree
containment is checked from outside.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from sbx import winapi

JobObjectBasicProcessIdList = 3
MAX_TRACKED_PROCESSES = 128


class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
    _fields_ = [
        ("NumberOfAssignedProcesses", wintypes.DWORD),
        ("NumberOfProcessIdsInList", wintypes.DWORD),
        ("ProcessIdList", ctypes.c_size_t * MAX_TRACKED_PROCESSES),
    ]


def job_pids(job: int) -> list[int]:
    """The PIDs currently assigned to a Job Object."""
    info = JOBOBJECT_BASIC_PROCESS_ID_LIST()
    info.NumberOfAssignedProcesses = MAX_TRACKED_PROCESSES
    ret_len = wintypes.DWORD()
    ok = winapi.kernel32.QueryInformationJobObject(
        job, JobObjectBasicProcessIdList,
        ctypes.byref(info), ctypes.sizeof(info),
        ctypes.byref(ret_len),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return [
        info.ProcessIdList[i]
        for i in range(info.NumberOfProcessIdsInList)
    ]


def sandbox_job_pids(sandbox_name: str) -> list[int]:
    """The PIDs a named sandbox owns, opening and closing the job."""
    job = winapi.open_job_object(
        f"Global\\sbx-job-{sandbox_name}", winapi.JOB_OBJECT_QUERY
    )
    try:
        return job_pids(job)
    finally:
        winapi.close_handle(job)
