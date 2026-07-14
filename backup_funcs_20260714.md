# 备份: MemoryModulePP 关键函数实现
# 生成日期: 2026-07-14
# 用途: 在 git checkout HEAD 后恢复

============================================================
# 1. Loader.cpp - LdrLoadDllMemoryExW, LdrUnloadDllMemory, 
#    LdrUnloadDllMemoryAndExitThread, LdrQuerySystemMemoryModuleFeatures
#    (包含我们对主路径的修改: TLS 拆分 + InitCache + EraseHeaders BEFORE DllMain)
============================================================

--- Loader.cpp 完整内容 ---

#include "stdafx.h"
#include <cmath>
#include <string.h>
#include "MmpLog.h"

// Forward declaration - defined in Utils.cpp
FARPROC NTAPI MmpGetProcAddress(_In_ PVOID ModuleBase, _In_ LPCSTR ExportName);

#ifdef _USRDLL
#if (defined(_WIN64) || defined(_M_ARM))
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=LdrUnloadDllMemoryAndExitThread")
#else
#pragma comment(linker,"/export:LdrUnloadDllMemoryAndExitThread=_LdrUnloadDllMemoryAndExitThread@8")
#pragma comment(linker,"/export:FreeLibraryMemoryAndExitThread=_LdrUnloadDllMemoryAndExitThread@8")
#endif
#endif

NTSTATUS NTAPI LdrMapDllMemory(
    _In_ HMEMORYMODULE ViewBase,
    _In_ DWORD dwFlags,
    _In_opt_ PCWSTR DllName,
    _In_opt_ PCWSTR lpFullDllName,
    _Out_opt_ PLDR_DATA_TABLE_ENTRY* DataTableEntry) {

    UNICODE_STRING FullDllName, BaseDllName;
    PIMAGE_NT_HEADERS NtHeaders;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    HANDLE heap = NtCurrentPeb()->ProcessHeap;

    //
    // PE headers are still intact at this point (they are erased later in
    // LdrLoadDllMemoryExW after all initialization is complete).
    // RtlImageNtHeader should succeed.
    //
    // NOTE: The fallback path below is a placeholder only. If headers have
    // already been erased (e.g. re-mapping an already-loaded module),
    // RtlAllocateDataTableEntry and RtlInitializeLdrDataTableEntry will
    // fail because they depend on PE header fields (SizeOfImage, EntryPoint,
    // subsystem, etc.) that are no longer available. This function is only
    // called once during initial load, before headers are erased, so this
    // is not a practical concern.
    //
    PMEMORYMODULE module = MapMemoryModuleHandle(ViewBase);
    if (!module) return STATUS_INVALID_IMAGE_FORMAT;

    NtHeaders = RtlImageNtHeader(ViewBase);
    if (!NtHeaders) {
        // Fallback: use cached metadata from MEMORYMODULE struct.
        // RtlAllocateDataTableEntry and RtlInitializeLdrDataTableEntry
        // need the image base and size, which we have cached.
    }

    if (!(LdrEntry = RtlAllocateDataTableEntry(ViewBase))) return STATUS_NO_MEMORY;

    if (!NT_SUCCESS(RtlResolveDllNameUnicodeString(DllName, lpFullDllName, &BaseDllName, &FullDllName))) {
        RtlFreeHeap(heap, 0, LdrEntry);
        return STATUS_NO_MEMORY;
    }

    if (!RtlInitializeLdrDataTableEntry(LdrEntry, dwFlags, ViewBase, BaseDllName, FullDllName)) {
        RtlFreeHeap(heap, 0, LdrEntry);
        RtlFreeHeap(heap, 0, BaseDllName.Buffer);
        RtlFreeHeap(heap, 0, FullDllName.Buffer);
        return STATUS_UNSUCCESSFUL;
    }

    RtlInsertMemoryTableEntry(LdrEntry);
    if (DataTableEntry)*DataTableEntry = LdrEntry;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI LdrLoadDllMemoryExW(
    _Out_ HMEMORYMODULE* BaseAddress,
    _Out_opt_ PVOID* LdrEntry,
    _In_ DWORD dwFlags,
    _In_ LPVOID BufferAddress,
    _In_ size_t BufferSize,
    _In_opt_ LPCWSTR DllName,
    _In_opt_ LPCWSTR DllFullName) {
    PMEMORYMODULE module = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
    PIMAGE_NT_HEADERS headers = nullptr;

    MMP_LOG("load begin: name=%ls size=%zu flags=0x%08X",
        DllName ? DllName : L"(null)", BufferSize, dwFlags);

    if (BufferSize)return STATUS_INVALID_PARAMETER_5;
    __try {
        *BaseAddress = nullptr;
        if (LdrEntry)*LdrEntry = nullptr;

        if (!RtlIsValidImageBuffer(BufferAddress, &BufferSize) && !(dwFlags & LOAD_FLAGS_PASS_IMAGE_CHECK)) {
            status = STATUS_INVALID_IMAGE_FORMAT;
        }

        if (MmpGlobalDataPtr == nullptr) {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status))return status;

    if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
        dwFlags &= LOAD_FLAGS_NOT_MAP_DLL;
        DllName = DllFullName = nullptr;
    }
    if (dwFlags & LOAD_FLAGS_USE_DLL_NAME && (!DllName || !DllFullName))return STATUS_INVALID_PARAMETER_3;

    if (DllName) {
        int length = (int)wcslen(DllName);
        PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
        PIMAGE_NT_HEADERS h1 = RtlImageNtHeader(BufferAddress), h2 = nullptr;
        if (!h1)return STATUS_INVALID_IMAGE_FORMAT;

        while (ListEntry != ListHead) {
            PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            ListEntry = ListEntry->Flink;

            if (!CurEntry->InMemoryOrderLinks.Flink) continue;

            int entryNameLength = (int)(CurEntry->BaseDllName.Length / sizeof(wchar_t));
            int dist = entryNameLength - length;
            bool equal = false;
            if (dist == 0 || dist == 4) {
                equal = CurEntry->BaseDllName.Buffer && !_wcsnicmp(DllName, CurEntry->BaseDllName.Buffer, length);
            }
            else {
                continue;
            }

            if (equal && CurEntry->BaseDllName.Buffer && CurEntry->DllBase) {
                if (!(module = MapMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)))continue;

                bool sameImage = false;
                __try {
                    h2 = RtlImageNtHeader(CurEntry->DllBase);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    h2 = nullptr;
                }

                if (h2) {
                    sameImage =
                        (h1->OptionalHeader.SizeOfCode == h2->OptionalHeader.SizeOfCode) &&
                        (h1->OptionalHeader.SizeOfHeaders == h2->OptionalHeader.SizeOfHeaders);
                }
                else {
                    sameImage =
                        (h1->OptionalHeader.SizeOfCode == module->SizeOfCode) &&
                        (h1->OptionalHeader.SizeOfHeaders == module->SizeofHeaders);
                }

                if (sameImage) {
                    if (!module->UseReferenceCount || dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT)return STATUS_INVALID_PARAMETER_3;
                    RtlUpdateReferenceCount(module, FLAG_REFERENCE);
                    *BaseAddress = (HMEMORYMODULE)CurEntry->DllBase;
                    if (LdrEntry)*LdrEntry = CurEntry;
                    return STATUS_SUCCESS;
                }
            }
        }
    }

    MMP_LOG("MemoryLoadLibrary: mapping image (size=%zu)...", BufferSize);
    status = MemoryLoadLibrary(BaseAddress, BufferAddress, (DWORD)BufferSize);
    MMP_LOG("MemoryLoadLibrary: base=0x%p status=0x%08X", (void*)*BaseAddress, (unsigned)status);
    if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)return status;

    if (!(module = MapMemoryModuleHandle(*BaseAddress))) {
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        DebugBreak();
        ExitProcess(STATUS_INVALID_ADDRESS);
        TerminateProcess(NtCurrentProcess(), STATUS_INVALID_ADDRESS);
    }
    module->loadFromLdrLoadDllMemory = true;

    if (module->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
        dwFlags |= LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION;

    headers = RtlImageNtHeader(*BaseAddress);

    if (dwFlags & LOAD_FLAGS_NOT_MAP_DLL) {
        MMP_LOG("[NOT_MAP_DLL] entering not-map path");
        do {
            if (!headers) { status = STATUS_INVALID_IMAGE_FORMAT; break; }
            status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
            if (!NT_SUCCESS(status))break;
            if (!MemorySetSectionProtection(headers)) { status = STATUS_ACCESS_DENIED; break; }
            if (!LdrpExecuteTLS(module) || !LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
                status = STATUS_DLL_INIT_FAILED; break;
            }
        } while (false);
        if (NT_SUCCESS(status)) {
            if (module->AllocatedWithOphion) { MmpErasePeHeaders(*BaseAddress); }
        } else {
            MemoryFreeLibrary(*BaseAddress);
        }
        return status;
    }

    do {
        status = LdrMapDllMemory(*BaseAddress, dwFlags, DllName, DllFullName, &ModuleEntry);
        MMP_LOG("LdrMapDllMemory: status=0x%08X", (unsigned)status);
        if (!NT_SUCCESS(status))break;

        module->MappedDll = true;
        module->LdrEntry = ModuleEntry;

        if (headers) {
            status = MemoryResolveImportTable(LPBYTE(*BaseAddress), headers, module);
            MMP_LOG("imports resolved status=0x%08X", (unsigned)status);
            if (!NT_SUCCESS(status))break;
            if (!MemorySetSectionProtection(headers)) { MMP_LOG("MemorySetSectionProtection FAILED"); status = STATUS_ACCESS_DENIED; break; }
            MMP_LOG("section protection set");
        }

        if (!(dwFlags & LOAD_FLAGS_NOT_USE_REFERENCE_COUNT))module->UseReferenceCount = true;

        if (!(dwFlags & LOAD_FLAGS_NOT_ADD_INVERTED_FUNCTION)) {
            status = RtlInsertInvertedFunctionTable((PVOID)module->codeBase, module->SizeOfImage);
            if (status == STATUS_NO_MEMORY) {
                status = RtlRegisterDynamicFunctionTable((PVOID)module->codeBase);
                if (NT_SUCCESS(status)) { module->DynamicFunctionTableEntry = true; }
            }
            if (!NT_SUCCESS(status)) break;
            if (!module->DynamicFunctionTableEntry) { module->InsertInvertedFunctionTableEntry = true; }
        }

        if (!(dwFlags & LOAD_FLAGS_NOT_HANDLE_TLS)) {
            status = MmpGlobalDataPtr->MmpFunctions->_MmpHandleTlsData(ModuleEntry);
            if (!NT_SUCCESS(status)) {
                if (dwFlags & LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS) status = 0x7fffffff;
                if (!NT_SUCCESS(status))break;
            } else { module->TlsHandled = true; }
        }

        if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) { MmpPreInitializeHooksForDotNet(); }

        MMP_LOG("TLS + DllMain(DLL_PROCESS_ATTACH)...");
        if (!LdrpExecuteTLS(module)) {
            MMP_LOG("TLS FAILED -> STATUS_DLL_INIT_FAILED");
            status = STATUS_DLL_INIT_FAILED;
            break;
        }
        // --- Init resource cache + erase headers BEFORE DllMain ---
        {
            typedef void(*fnInitCache)(PVOID, int);
            fnInitCache initCache = (fnInitCache)MmpGetProcAddress(*BaseAddress, "rdoc_InitResourceCache_Export");
            if (initCache) {
                initCache(*BaseAddress, 256);
                MMP_LOG("Resource cache initialized (pre-erasure)");
            }
        }
        MMP_LOG("MmpErasePeHeaders: BEFORE DllMain base=0x%p", (void*)*BaseAddress);
        MmpErasePeHeaders(*BaseAddress);
        MMP_LOG("PE headers erased (SizeOfHeaders zeroed)");
        MMP_LOG(">>> calling DllMain (LdrpCallInitializers DLL_PROCESS_ATTACH)...");
        if (!LdrpCallInitializers(module, DLL_PROCESS_ATTACH)) {
            MMP_LOG("DllMain FAILED -> STATUS_DLL_INIT_FAILED");
            status = STATUS_DLL_INIT_FAILED;
            break;
        }
        MMP_LOG("TLS + DllMain ok");

        if (dwFlags & LOAD_FLAGS_HOOK_DOT_NET) { MmpInitializeHooksForDotNet(); }
    } while (false);

    if (NT_SUCCESS(status)) {
        MMP_LOG("load end: SUCCESS base=0x%p status=0x%08X", (void*)*BaseAddress, (unsigned)status);
        if (LdrEntry)*LdrEntry = ModuleEntry;
    } else {
        MMP_LOG("load end: FAILED status=0x%08X -> unloading", (unsigned)status);
        LdrUnloadDllMemory(*BaseAddress);
        *BaseAddress = nullptr;
    }
    return status;
}

NTSTATUS NTAPI LdrUnloadDllMemory(_In_ HMEMORYMODULE BaseAddress) {
    PLDR_DATA_TABLE_ENTRY CurEntry;
    ULONG count = 0;
    NTSTATUS status = STATUS_SUCCESS;
    PMEMORYMODULE module = MapMemoryModuleHandle(BaseAddress);
    do {
        if (!module || !module->loadFromLdrLoadDllMemory) { status = STATUS_INVALID_HANDLE; break; }
        if (MmpGlobalDataPtr == nullptr) { status = STATUS_INVALID_PARAMETER; break; }
        if (!module->MappedDll) { module->underUnload = true; status = (MemoryFreeLibrary(BaseAddress) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL); break; }
        CurEntry = (PLDR_DATA_TABLE_ENTRY)module->LdrEntry;
        if (module->SizeOfImage != CurEntry->SizeOfImage) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        if (module->UseReferenceCount) { status = RtlGetReferenceCount(module, &count); if (!NT_SUCCESS(status)) break; }
        if (count & ~1) { status = RtlUpdateReferenceCount(module, FLAG_DEREFERENCE); break; }
        module->underUnload = true;
        if (module->initialized) {
            PLDR_INIT_ROUTINE((LPVOID)(module->codeBase + module->AddressOfEntryPoint))(
                (HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
        }
        if (module->MappedDll) {
            if (module->InsertInvertedFunctionTableEntry) { status = RtlRemoveInvertedFunctionTable(BaseAddress); if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY); }
            if (module->DynamicFunctionTableEntry) { status = RtlUnregisterDynamicFunctionTable(BaseAddress); if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
            if (module->TlsHandled) { status = MmpGlobalDataPtr->MmpFunctions->_MmpReleaseTlsEntry(CurEntry); if (!NT_SUCCESS(status)) __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
            if (!RtlFreeLdrDataTableEntry(CurEntry)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        if (!MemoryFreeLibrary(BaseAddress)) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    } while (false);
    return status;
}

DECLSPEC_NORETURN
VOID NTAPI LdrUnloadDllMemoryAndExitThread(_In_ HMEMORYMODULE BaseAddress, _In_ DWORD dwExitCode) {
    LdrUnloadDllMemory(BaseAddress);
    RtlExitUserThread(dwExitCode);
}

NTSTATUS NTAPI LdrQuerySystemMemoryModuleFeatures(_Out_ PDWORD pFeatures) {
    NTSTATUS status = STATUS_SUCCESS;
    __try { *pFeatures = MmpGlobalDataPtr->MmpFeatures; }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    return status;
}

============================================================
# 2. LoadDllMemoryApi.cpp - LoadLibraryMemory, LoadLibraryMemoryExA,
#    LoadLibraryMemoryExW, FreeLibraryMemory
============================================================

--- LoadDllMemoryApi.cpp 完整内容 ---

#include "stdafx.h"
#include <cstdlib>

HMEMORYMODULE WINAPI LoadLibraryMemoryExW(
    _In_ PVOID BufferAddress,
    _In_ size_t Reserved,
    _In_opt_ LPCWSTR DllBaseName,
    _In_opt_ LPCWSTR DllFullName,
    _In_ DWORD Flags) {
    HMEMORYMODULE hMemoryModule = nullptr;
    NTSTATUS status = LdrLoadDllMemoryExW(&hMemoryModule, nullptr, Flags, BufferAddress, Reserved, DllBaseName, DllFullName);
    if (!NT_SUCCESS(status) || status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
        SetLastError(RtlNtStatusToDosError(status));
    }
    return hMemoryModule;
}

HMEMORYMODULE WINAPI LoadLibraryMemoryExA(
    _In_ PVOID BufferAddress,
    _In_ size_t Reserved,
    _In_opt_ LPCSTR DllBaseName,
    _In_opt_ LPCSTR DllFullName,
    _In_ DWORD Flags) {
    LPWSTR _DllName = nullptr, _DllFullName = nullptr;
    size_t size;
    HMEMORYMODULE result = nullptr;
    HANDLE heap = NtCurrentPeb()->ProcessHeap;
    do {
        if (DllBaseName) {
            size = strlen(DllBaseName) + 1;
            _DllName = (LPWSTR)RtlAllocateHeap(heap, 0, sizeof(WCHAR) * size);
            if (!_DllName) { RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES); break; }
            mbstowcs_s(nullptr, _DllName, size, DllBaseName, size);
        }
        if (DllFullName) {
            size = strlen(DllFullName) + 1;
            _DllFullName = (LPWSTR)RtlAllocateHeap(heap, 0, sizeof(WCHAR) * size);
            if (!_DllFullName) { RtlNtStatusToDosError(STATUS_INSUFFICIENT_RESOURCES); break; }
            mbstowcs_s(nullptr, _DllFullName, size, DllFullName, size);
        }
        result = LoadLibraryMemoryExW(BufferAddress, 0, _DllName, _DllFullName, Flags);
    } while (false);
    RtlFreeHeap(heap, 0, _DllName);
    RtlFreeHeap(heap, 0, _DllFullName);
    return result;
}

HMEMORYMODULE WINAPI LoadLibraryMemory(_In_ PVOID BufferAddress) {
    return LoadLibraryMemoryExW(BufferAddress, 0, nullptr, nullptr, 0);
}

BOOL WINAPI FreeLibraryMemory(_In_ HMEMORYMODULE hMemoryModule) {
    NTSTATUS status = LdrUnloadDllMemory(hMemoryModule);
    if (!NT_SUCCESS(status)) { SetLastError(RtlNtStatusToDosError(status)); return FALSE; }
    return TRUE;
}


============================================================
# 3. Initialize.cpp - MmInitialize, MmCleanup, MmpGlobalDataPtr
============================================================

--- Initialize.cpp 关键部分 ---

NTSTATUS NTAPI MmInitialize() {
    NTSTATUS status;
    PVOID cookie;
    LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &cookie);
    __try { status = InitializeLockHeld(); }
    __finally { LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie); }
    return status;
}

NTSTATUS CleanupLockHeld() {
    PLIST_ENTRY ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList, ListEntry = ListHead->Flink;
    PLDR_DATA_TABLE_ENTRY CurEntry;
    while (ListEntry != ListHead) {
        CurEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ListEntry = ListEntry->Flink;
        if (IsValidMemoryModuleHandle((HMEMORYMODULE)CurEntry->DllBase)) {
            return STATUS_NOT_SUPPORTED;
        }
    }
    if (--MmpGlobalDataPtr->ReferenceCount > 0) { return STATUS_SUCCESS; }
    MmpTlsCleanup();
    MmpCleanupDotNetHooks();
    NtUnmapViewOfSection(NtCurrentProcess(), MmpGlobalDataPtr->BaseAddress);
    MmpGlobalDataPtr = nullptr;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI MmCleanup() {
    NTSTATUS status;
    PVOID cookie;
    LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &cookie);
    __try {
        if (MmpGlobalDataPtr == nullptr) { status = STATUS_ACCESS_VIOLATION; __leave; }
        status = CleanupLockHeld();
    }
    __finally { LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie); }
    return status;
}

// MmpGlobalDataPtr 在 Initialize.cpp 中定义:
// PMEMORYMODULE_GLOBAL_DATA MmpGlobalDataPtr = nullptr;


============================================================
# 4. MemoryModule.cpp - MmpErasePeHeaders
============================================================

VOID NTAPI MmpErasePeHeaders(_In_ HMEMORYMODULE ModuleBase) {
    if (!ModuleBase) return;
    PMEMORYMODULE module = MapMemoryModuleHandle(ModuleBase);
    if (!module) return;
    DWORD eraseSize = module->SizeofHeaders;
    if (eraseSize > 0) { RtlZeroMemory(ModuleBase, eraseSize); }
}


============================================================
# 5. MemoryModule.cpp - MmpLdrLoadDllMemoryExW_TriggerJump (x64)
============================================================

#if defined(_WIN64)

NTSTATUS NTAPI MmpLdrLoadDllMemoryExW_TriggerJump(
    _In_ LPCVOID DllBuffer,
    _In_ DWORD DllSize,
    _In_ UINT64 TriggerVa,
    _Out_opt_ UINT64* OutDllRemoteVa,
    _Out_opt_ UINT64* OutScRemoteVa,
    _In_opt_ LPCWSTR DllName,
    _In_opt_ LPCWSTR DllFullName)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE dev = INVALID_HANDLE_VALUE;
    LPBYTE dll_remote_va = nullptr;
    UINT64 dll_alloc_size = 0;
    LPBYTE sc_remote_va = nullptr;
    BYTE shellcode[128] = {};
    DWORD sc_size = 0;
    UINT64 LdrLoadVa = 0;

    SIZE_T dll_name_bytes = 0;
    SIZE_T dll_full_name_bytes = 0;
    UINT64 dll_name_remote_va = 0;
    UINT64 dll_full_name_remote_va = 0;

    if (DllName) { dll_name_bytes = (wcslen(DllName) + 1) * sizeof(WCHAR); }
    if (DllFullName) { dll_full_name_bytes = (wcslen(DllFullName) + 1) * sizeof(WCHAR); }

    if (!DllBuffer || DllSize == 0 || DllSize > 64 * 1024 * 1024) { return STATUS_INVALID_PARAMETER; }

    LdrLoadVa = (UINT64)LdrLoadDllMemoryExW;
    if (!LdrLoadVa) { return STATUS_PROCEDURE_NOT_FOUND; }

    // 1. Allocate RW memory for DLL data via IOCTL_ALLOC_SHADOW_MEMORY
    dev = CreateFileW(L"\\\\.\\OphionTest", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (dev == INVALID_HANDLE_VALUE) { return STATUS_DEVICE_NOT_CONNECTED; }

    TD_ALLOC_SHADOW_MEMORY_PARAMS alloc = {};
    alloc.target_pid = (UINT64)GetCurrentProcessId();
    alloc.size = (UINT64)DllSize + 8 + dll_name_bytes + dll_full_name_bytes;
    alloc.need_execute = 0;
    alloc.alloc_protect = PAGE_READWRITE;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_ALLOC_SHADOW_MEMORY, &alloc, sizeof(alloc), &alloc, sizeof(alloc), &bytes, nullptr);
    if (!ok || bytes < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS) || alloc.status != 0 || !alloc.base_va) {
        CloseHandle(dev); return STATUS_NO_MEMORY;
    }
    dll_remote_va = (LPBYTE)alloc.base_va;
    dll_alloc_size = (UINT64)alloc.size;

    // 2. Copy DLL data + DllName/DllFullName strings
    __try {
        memcpy(dll_remote_va, DllBuffer, DllSize);
        LPBYTE str_dst = dll_remote_va + DllSize + 8;
        if (dll_name_bytes > 0) { memcpy(str_dst, DllName, dll_name_bytes); dll_name_remote_va = (UINT64)str_dst; str_dst += dll_name_bytes; }
        if (dll_full_name_bytes > 0) { memcpy(str_dst, DllFullName, dll_full_name_bytes); dll_full_name_remote_va = (UINT64)str_dst; }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        TD_ALLOC_SHADOW_MEMORY_PARAMS free_p = {}; free_p.target_pid = (UINT64)GetCurrentProcessId(); free_p.base_va = (UINT64)dll_remote_va; free_p.size = dll_alloc_size; free_p.need_execute = 0; free_p.alloc_protect = PAGE_READWRITE;
        DeviceIoControl(dev, IOCTL_FREE_SHADOW_MEMORY, &free_p, sizeof(free_p), &free_p, sizeof(free_p), &bytes, nullptr);
        CloseHandle(dev); return STATUS_UNSUCCESSFUL;
    }

    // 3. Build shellcode (x64)
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0x83; shellcode[sc_size++] = 0xEC; shellcode[sc_size++] = 0x58; // sub rsp, 0x58
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0xB8; // mov rax, dll_full_name_remote_va
    memcpy(shellcode + sc_size, &dll_full_name_remote_va, sizeof(UINT64)); sc_size += 8;
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0x89; shellcode[sc_size++] = 0x44; shellcode[sc_size++] = 0x24; shellcode[sc_size++] = 0x30; // mov [rsp+0x30], rax
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0xB8; // mov rax, dll_name_remote_va
    memcpy(shellcode + sc_size, &dll_name_remote_va, sizeof(UINT64)); sc_size += 8;
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0x89; shellcode[sc_size++] = 0x44; shellcode[sc_size++] = 0x24; shellcode[sc_size++] = 0x28; // mov [rsp+0x28], rax
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0xC7; shellcode[sc_size++] = 0x84; shellcode[sc_size++] = 0x24; // mov qword ptr [rsp+0x20], 0
    shellcode[sc_size++] = 0x20; shellcode[sc_size++] = 0x00; shellcode[sc_size++] = 0x00; shellcode[sc_size++] = 0x00;
    shellcode[sc_size++] = 0x00; shellcode[sc_size++] = 0x00; shellcode[sc_size++] = 0x00; shellcode[sc_size++] = 0x00;
    shellcode[sc_size++] = 0x49; shellcode[sc_size++] = 0xB9; // mov r9, dll_remote_va
    memcpy(shellcode + sc_size, &dll_remote_va, sizeof(UINT64)); sc_size += 8;
    shellcode[sc_size++] = 0x45; shellcode[sc_size++] = 0x31; shellcode[sc_size++] = 0xC0; // xor r8d, r8d
    shellcode[sc_size++] = 0x31; shellcode[sc_size++] = 0xD2; // xor edx, edx
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0x8D; shellcode[sc_size++] = 0x4C; shellcode[sc_size++] = 0x24; shellcode[sc_size++] = 0x40; // lea rcx, [rsp+0x40]
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0xB8; // mov rax, LdrLoadVa
    memcpy(shellcode + sc_size, &LdrLoadVa, sizeof(UINT64)); sc_size += 8;
    shellcode[sc_size++] = 0xFF; shellcode[sc_size++] = 0xD0; // call rax
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0x8B; shellcode[sc_size++] = 0x44; shellcode[sc_size++] = 0x24; shellcode[sc_size++] = 0x40; // mov rax, [rsp+0x40]
    UINT64 moduleBaseOutVa = (UINT64)dll_remote_va + (UINT64)DllSize;
    shellcode[sc_size++] = 0x49; shellcode[sc_size++] = 0xBA; // mov r10, moduleBaseOutVa
    memcpy(shellcode + sc_size, &moduleBaseOutVa, sizeof(UINT64)); sc_size += 8;
    shellcode[sc_size++] = 0x49; shellcode[sc_size++] = 0x89; shellcode[sc_size++] = 0x02; // mov [r10], rax
    shellcode[sc_size++] = 0x48; shellcode[sc_size++] = 0x83; shellcode[sc_size++] = 0xC4; shellcode[sc_size++] = 0x58; // add rsp, 0x58
    shellcode[sc_size++] = 0xC3; // ret

    // 4. Allocate shellcode memory
    TD_ALLOC_SHADOW_MEMORY_PARAMS sc_alloc = {};
    sc_alloc.target_pid = (UINT64)GetCurrentProcessId();
    sc_alloc.size = 0x1000;
    sc_alloc.need_execute = 1;
    sc_alloc.alloc_protect = PAGE_READWRITE;
    bytes = 0;
    ok = DeviceIoControl(dev, IOCTL_ALLOC_SHADOW_MEMORY, &sc_alloc, sizeof(sc_alloc), &sc_alloc, sizeof(sc_alloc), &bytes, nullptr);
    if (!ok || bytes < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS) || sc_alloc.status != 0 || !sc_alloc.base_va) {
        TD_ALLOC_SHADOW_MEMORY_PARAMS free_p = {}; free_p.target_pid = (UINT64)GetCurrentProcessId(); free_p.base_va = (UINT64)dll_remote_va; free_p.size = dll_alloc_size; free_p.need_execute = 0; free_p.alloc_protect = PAGE_READWRITE;
        DeviceIoControl(dev, IOCTL_FREE_SHADOW_MEMORY, &free_p, sizeof(free_p), &free_p, sizeof(free_p), &bytes, nullptr);
        CloseHandle(dev); return STATUS_NO_MEMORY;
    }
    sc_remote_va = (LPBYTE)sc_alloc.base_va;

    // 5. Copy shellcode
    __try { memcpy(sc_remote_va, shellcode, sc_size); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 释放两个分配
        CloseHandle(dev); return STATUS_UNSUCCESSFUL;
    }

    // 6. Install trigger jump
    TD_TRIGGER_JUMP_PARAMS trigger = {};
    trigger.target_pid = (UINT64)GetCurrentProcessId();
    trigger.trigger_va = TriggerVa;
    trigger.jump_to_va = (UINT64)sc_remote_va;
    trigger.flags = 2;
    bytes = 0;
    ok = DeviceIoControl(dev, IOCTL_INSTALL_TRIGGER_JUMP, &trigger, sizeof(trigger), &trigger, sizeof(trigger), &bytes, nullptr);
    if (!ok || bytes < sizeof(TD_TRIGGER_JUMP_PARAMS) || trigger.status != 0) {
        status = STATUS_UNSUCCESSFUL;
        CloseHandle(dev);
        return status;
    }
    CloseHandle(dev);

    if (OutDllRemoteVa) *OutDllRemoteVa = (UINT64)dll_remote_va;
    if (OutScRemoteVa) *OutScRemoteVa = (UINT64)sc_remote_va;
    return STATUS_SUCCESS;
}

#else // !_WIN64

NTSTATUS NTAPI MmpLdrLoadDllMemoryExW_TriggerJump(
    _In_ LPCVOID DllBuffer,
    _In_ DWORD DllSize,
    _In_ UINT64 TriggerVa,
    _Out_opt_ UINT64* OutDllRemoteVa,
    _Out_opt_ UINT64* OutScRemoteVa,
    _In_opt_ LPCWSTR DllName,
    _In_opt_ LPCWSTR DllFullName)
{
    UNREFERENCED_PARAMETER(DllBuffer);
    UNREFERENCED_PARAMETER(DllSize);
    UNREFERENCED_PARAMETER(TriggerVa);
    UNREFERENCED_PARAMETER(OutDllRemoteVa);
    UNREFERENCED_PARAMETER(OutScRemoteVa);
    UNREFERENCED_PARAMETER(DllName);
    UNREFERENCED_PARAMETER(DllFullName);
    return STATUS_NOT_SUPPORTED;
}

#endif // _WIN64


============================================================
# 6. MmpSetForceCrashRVA
============================================================

// 在 Loader.cpp 顶部, #include 之后, LdrMapDllMemory 之前添加:

// ---------------------------------------------------------------------------
//  ForceCrash RVA: set by the caller via MmpSetForceCrashRVA() before loading.
//  When non-zero, the loader NOPs out the DLL's ForceCrash function at
//  codeBase + this RVA right before erasing PE headers + calling DllMain.
//  This prevents assertion-triggered crashes when the DLL's runtime code
//  reads its own (now erased) PE headers.
// ---------------------------------------------------------------------------
static DWORD g_ForceCrashRVA = 0;

VOID NTAPI MmpSetForceCrashRVA(_In_ DWORD rva)
{
    g_ForceCrashRVA = rva;
}