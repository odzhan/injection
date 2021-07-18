/**
  Copyright © 2020 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef WER_H
#define WER_H

// WerRegisterCustomMetadata
typedef struct _WER_METADATA {
    PVOID                Next;
    WCHAR                Key[64];
    WCHAR                Value[128];
} WER_METADATA, *PWER_METADATA;

// WerRegisterFile
// Registers a file to be collected when WER creates an error report.
typedef struct _WER_FILE {
    USHORT               Flags;
    WCHAR                Path[MAX_PATH];
} WER_FILE, *PWER_FILE;

// WerRegisterExcludedMemoryBlock
// Marks a memory block (that is normally included by default in error reports) to be excluded from the error report.
//
// WerRegisterMemoryBlock
// Registers a memory block to be collected when WER creates an error report.
typedef struct _WER_MEMORY {
    PVOID                Address;   // The starting address of the memory block.
    ULONG                Size;      // The size of the memory block, in bytes.
} WER_MEMORY, *PWER_MEMORY;

typedef struct _WER_GATHER {
    PVOID                Next;
    USHORT               Flags;    
    union {
      WER_FILE           File;
      WER_MEMORY         Memory;
    } v;
} WER_GATHER, *PWER_GATHER;

// WerRegisterAdditionalProcess
typedef struct _WER_DUMP_COLLECTION {
    PVOID                Next;
    DWORD                ProcessId;              // The Id of the process to register.
    DWORD                ThreadId;   // The Id of a thread within the registered process from which more information is requested.
} WER_DUMP_COLLECTION, *PWER_DUMP_COLLECTION;

typedef struct _WER_RUNTIME_DLL {
    PVOID                Next;
    ULONG                Length;                 // total length of this structure
    PVOID                Context;                // passed to callback in DLL
    WCHAR                CallbackDllPath[MAX_PATH];
} WER_RUNTIME_DLL, *PWER_RUNTIME_DLL;

// GetApplicationRecoveryCallback to read from remote process
// RegisterApplicationRecoveryCallback
typedef struct _WER_RECOVERY_INFO {
    ULONG                Length;
    PVOID                Callback;
    PVOID                Parameter;
    HANDLE               Started;
    HANDLE               Finished;            // read by ApplicationRecoveryFinished
    HANDLE               InProgress;          // read by ApplicationRecoveryInProgress
    LONG                 LastError;
    BOOL                 Successful;
    DWORD                PingInterval;
    DWORD                Flags;
} WER_RECOVERY_INFO, *PWER_RECOVERY_INFO;

typedef struct _WER_HEAP_MAIN_HEADER {
    WCHAR                Signature[16];                // HEAP_SIGNATURE 
    LIST_ENTRY           ListHead;
    HANDLE               Mutex;
    PVOID                FreeHeap;
    PVOID                FreeCount;
} WER_HEAP_MAIN_HEADER, *PWER_HEAP_MAIN_HEADER;

typedef struct _WER_PEB_HEADER_BLOCK {
    LONG                 Length;
    WCHAR                Signature[16];
    WCHAR                AppDataRelativePath[64];
    WCHAR                RestartCommandLine[RESTART_MAX_CMD_LINE];
    WER_RECOVERY_INFO    RecoveryInfo;
    PWER_GATHER          Gather;
    PWER_METADATA        MetaData;
    PWER_RUNTIME_DLL     RuntimeDll;
    PWER_DUMP_COLLECTION DumpCollection;
    LONG                 GatherCount;
    LONG                 MetaDataCount;
    LONG                 DumpCount;
    LONG                 Flags;
    WER_HEAP_MAIN_HEADER MainHeader;
    PVOID                Reserved;
} WER_PEB_HEADER_BLOCK, *PWER_PEB_HEADER_BLOCK;

#endif
