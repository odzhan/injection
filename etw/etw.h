/**
  Copyright © 2019 Odzhan. All Rights Reserved.

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
  
#ifndef ETW_H
#define ETW_H

#include "../ntlib/util.h"
#include "../ntlib/ntddk.h"

#include <evntrace.h>
#include <pla.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <Evntcons.h>

// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/control/index.htm

typedef enum _ETW_TRACE_CONTROL_CODE {
    EtwStartLoggerCode = 1,
    EtwStopLoggerCode = 2,
    EtwQueryLoggerCode = 3,
    EtwUpdateLoggerCode = 4,
    EtwFlushLoggerCode = 5,
    EtwConnect = 11,
    EtwActivityIdCreate = 12,
    EtwWdiScenarioCode = 13,
    EtwDisconnect = 14,
    EtwRegisterGuid = 15,
    EtwReceiveNotification = 16,
    EtwEnableGuid = 17,
    EtwSendReplyDataBlock = 18,
    EtwReceiveReplyDataBlock = 19,
    
    EtwWdiSemUpdate = 20
} ETW_TRACE_CONTROL_CODE;

#define EventActivityIdControl  EtwEventActivityIdControl
#define EventEnabled            EtwEventEnabled
#define EventProviderEnabled    EtwEventProviderEnabled
#define EventRegister           EtwEventRegister
#define EventSetInformation     EtwEventSetInformation
#define EventUnregister         EtwEventUnregister
#define EventWrite              EtwEventWrite
#define EventWriteEndScenario   EtwEventWriteEndScenario
#define EventWriteEx            EtwEventWriteEx
#define EventWriteStartScenario EtwEventWriteStartScenario
#define EventWriteString        EtwEventWriteString
#define EventWriteTransfer      EtwEventWriteTransfer

#include <evntprov.h>
#include <evntrace.h>
#include <evntcons.h>

//////////////////////////////////////////////////////////////////////////
// Macros.
//////////////////////////////////////////////////////////////////////////

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~((ULONG_PTR)(alignment) - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + (alignment) - 1), alignment))

#define ALIGN_DOWN_POINTER_BY(address, alignment) \
    ((PVOID)((ULONG_PTR)(address) & ~((ULONG_PTR)(alignment) - 1)))

#define ALIGN_UP_POINTER_BY(address, alignment) \
    (ALIGN_DOWN_POINTER_BY(((ULONG_PTR)(address) + (alignment) - 1), alignment))

#define ALIGN_DOWN(length, type) \
    ALIGN_DOWN_BY(length, sizeof(type))

#define ALIGN_UP(length, type) \
    ALIGN_UP_BY(length, sizeof(type))

#define ALIGN_DOWN_POINTER(address, type) \
    ALIGN_DOWN_POINTER_BY(address, sizeof(type))

#define ALIGN_UP_POINTER(address, type) \
    ALIGN_UP_POINTER_BY(address, sizeof(type))

#define ETW_SESSION_HANDLE(WmiLoggerInformation) \
  ((USHORT)(((PWMI_LOGGER_INFORMATION)(WmiLoggerInformation))->Wnode.HistoricalContext))

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define EVENT_TRACE_CLOCK_RAW           0x00000000  // Use Raw timestamp
#define EVENT_TRACE_CLOCK_PERFCOUNTER   0x00000001  // Use HighPerfClock (Default)
#define EVENT_TRACE_CLOCK_SYSTEMTIME    0x00000002  // Use SystemTime
#define EVENT_TRACE_CLOCK_CPUCYCLE      0x00000003  // Use CPU cycle counter

#define SINGLE_LIST_ENTRY_FREE          ((PSINGLE_LIST_ENTRY)0)
#define SINGLE_LIST_ENTRY_MARKED        ((PSINGLE_LIST_ENTRY)1)


//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _ETW_NOTIFICATION_TYPE {
    EtwNotificationTypeNoReply = 1,     // No data block reply
    EtwNotificationTypeLegacyEnable,    // Enable notification for RegisterTraceGuids
    EtwNotificationTypeEnable,          // Enable notification for EventRegister
    EtwNotificationTypePrivateLogger,   // Private logger notification for ETW
    EtwNotificationTypePerflib,         // PERFLIB V2 counter data request/delivery block
    EtwNotificationTypeAudio,           // Private notification for audio policy
    EtwNotificationTypeSession,         // Session related ETW notifications
    EtwNotificationTypeReserved,        // For internal use (test)
    EtwNotificationTypeCredentialUI,    // Private notification for media center elevation detection
    EtwNotificationTypeInProcSession,   // Private in-proc session related ETW notifications
    EtwNotificationTypeMax

} ETW_NOTIFICATION_TYPE;

typedef enum _ETW_BUFFER_STATE {
    EtwBufferStateFree = 0,
    EtwBufferStateGeneralLogging = 1,
    EtwBufferStateCSwitch = 2,
    EtwBufferStateFlush = 3,
    EtwBufferStatePendingCompression = 4,
    EtwBufferStateCompressed = 5,
    EtwBufferStatePlaceholder = 6,
    EtwBufferStateMaximum = 7,
} ETW_BUFFER_STATE;

typedef enum _ETW_FUNCTION_CODE {
    EtwFunctionStartTrace = 1,
    EtwFunctionStopTrace = 2,
    EtwFunctionQueryTrace = 3,
    EtwFunctionUpdateTrace = 4,
    EtwFunctionFlushTrace = 5,
    EtwFunctionIncrementTraceFile = 6,

    EtwFunctionRealtimeConnect = 11,
    EtwFunctionWdiDispatchControl = 13,
    EtwFunctionRealtimeDisconnectConsumerByHandle = 14,
    EtwFunctionReceiveNotification = 16,
    EtwFunctionTraceEnableGuid = 17,
    EtwFunctionSendReplyDataBlock = 18,
    EtwFunctionReceiveReplyDataBlock = 19,
    EtwFunctionWdiUpdateSem = 20,
    EtwFunctionGetTraceGuidList = 21,
    EtwFunctionGetTraceGuidInfo = 22,
    EtwFunctionEnumerateTraceGuids = 23,
    EtwFunctionRegisterSecurityProvider = 24,
    EtwFunctionQueryReferenceTime = 25,
    EtwFunctionTrackProviderBinary = 26,
    EtwFunctionAddNotificationEvent = 27,
    EtwFunctionUpdateDisallowList = 28,
    EtwFunctionUseDescriptorTypeUm = 31,
    EtwFunctionGetTraceGroupList = 32,
    EtwFunctionGetTraceGroupInfo = 33,
    EtwFunctionGetDisallowList = 34,
    EtwFunctionSetCompressionSettings = 35,
    EtwFunctionGetCompressionSettings = 36,
    EtwFunctionUpdatePeriodicCaptureState = 37,
    EtwFunctionGetPrivateSessionTraceHandle = 38,
    EtwFunctionRegisterPrivateSession = 39,
    EtwFunctionQuerySessionDemuxObject = 40,
    EtwFunctionSetProviderBinaryTracking = 41,
    EtwFunctionGetMaxLoggers = 42,
} ETW_FUNCTION_CODE;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _WMI_LOGGER_INFORMATION
{
  WNODE_HEADER Wnode;
  ULONG BufferSize;
  ULONG MinimumBuffers;
  ULONG MaximumBuffers;
  ULONG MaximumFileSize;
  ULONG LogFileMode;
  ULONG FlushTimer;
  ULONG EnableFlags;
  union
  {
    LONG AgeLimit;
    LONG FlushThreshold;
  };
  ULONG Wow;
  LONG Padding_719;
  union
  {
    PVOID LogFileHandle;
    ULONGLONG LogFileHandle64;
  };
  union
  {
    ULONG NumberOfBuffers;
    ULONG InstanceCount;
  };
  union
  {
    ULONG FreeBuffers;
    ULONG InstanceId;
  };
  union
  {
    ULONG EventsLost;
    ULONG NumberOfProcessors;
  };
  ULONG BuffersWritten;
  union
  {
    ULONG LogBuffersLost;
    ULONG Flags;
  };
  ULONG RealTimeBuffersLost;
  union
  {
    PVOID LoggerThreadId;
    ULONGLONG LoggerThreadId64;
  };
  union
  {
    UNICODE_STRING LogFileName;
    //STRING64 LogFileName64;
  };
  union
  {
    UNICODE_STRING LoggerName;
    //STRING64 LoggerName64;
  };
  ULONG RealTimeConsumerCount;
  ULONG SpareUlong;
  union
  {
    union
    {
      PVOID LoggerExtension;
      ULONGLONG LoggerExtension64;
    };
  }  DUMMYUNIONNAME10;
} WMI_LOGGER_INFORMATION, *PWMI_LOGGER_INFORMATION;

typedef struct _ETW_NOTIFICATION_HEADER
{
    ETW_NOTIFICATION_TYPE NotificationType; // Notification type
    ULONG                 NotificationSize; // Notification size in bytes

    ULONG                 Offset;           // Offset to the next notification
    BOOLEAN               ReplyRequested;   // Reply Requested

    ULONG                 Timeout;          // Timeout in milliseconds when requesting reply

    union {
        ULONG             ReplyCount;       // Out to sender: the number of notifications sent
        ULONG             NotifyeeCount;    // Out to notifyee: the order during notification
    };
    union
    {
      ULONGLONG ReplyHandle;
      PVOID ReplyObject;
      ULONG RegIndex;
    };
    ULONG TargetPID;
    ULONG SourcePID;
    GUID DestinationGuid;
    GUID SourceGuid;
} ETW_NOTIFICATION_HEADER, *PETW_NOTIFICATION_HEADER;

typedef struct _TRACE_ENABLE_CONTEXT {
    USHORT LoggerId;
    UCHAR Level;
    UCHAR InternalFlag;
    ULONG EnableFlags;
} TRACE_ENABLE_CONTEXT, *PTRACE_ENABLE_CONTEXT;

typedef struct _ETW_ENABLE_NOTIFICATION_PACKET {
    ETW_NOTIFICATION_HEADER DataBlockHeader;
    TRACE_ENABLE_INFO EnableInfo;
    TRACE_ENABLE_CONTEXT LegacyEnableContext;
    ULONG LegacyProviderEnabled;
    ULONG FilterCount;
} ETW_ENABLE_NOTIFICATION_PACKET, *PETW_ENABLE_NOTIFICATION_PACKET;

typedef struct _ETW_REF_CLOCK {
    LARGE_INTEGER StartTime;
    LARGE_INTEGER StartPerfClock;
} ETW_REF_CLOCK, *PETW_REF_CLOCK;

typedef struct _ETW_REALTIME_CONNECT_CONTEXT {
    ULONG LoggerId;
    ULONG ReserveBufferSpaceSize;
    ULONGLONG ReserveBufferSpacePtr;
    ULONGLONG ReserveBufferSpaceBitMapPtr;
    ULONGLONG DisconnectEvent;
    ULONGLONG DataAvailableEvent;
    ULONGLONG BufferListHeadPtr;
    ULONGLONG BufferCountPtr;
    ULONGLONG EventsLostCountPtr;
    ULONGLONG BuffersLostCountPtr;
    ULONGLONG ConnectHandle;
    ETW_REF_CLOCK RealtimeReferenceTime;
} ETW_REALTIME_CONNECT_CONTEXT, *PETW_REALTIME_CONNECT_CONTEXT;

typedef struct _WMI_BUFFER_HEADER {
  ULONG BufferSize;
  ULONG SavedOffset;
  volatile ULONG CurrentOffset;
  volatile LONG ReferenceCount;
  LARGE_INTEGER TimeStamp;
  LONGLONG SequenceNumber;
  union
  {
    struct
    {
      ULONGLONG ClockType : 3;
      ULONGLONG Frequency : 61;
    };
    SINGLE_LIST_ENTRY SlistEntry;
    struct _WMI_BUFFER_HEADER* NextBuffer;
  };
  ETW_BUFFER_CONTEXT ClientContext;
  ETW_BUFFER_STATE State;
  ULONG Offset;
  USHORT BufferFlag;
  USHORT BufferType;
  union
  {
    ULONG Padding1[4];
    ETW_REF_CLOCK ReferenceTime;
    LIST_ENTRY GlobalEntry;
    struct
    {
      PVOID Pointer0;
      PVOID Pointer1;
    };
  };
} WMI_BUFFER_HEADER, *PWMI_BUFFER_HEADER;

typedef ULONG (NTAPI *PETW_NOTIFICATION_CALLBACK) (
    PETW_NOTIFICATION_HEADER NotificationHeader,
    PVOID Context
    );
    
typedef struct _MCGEN_TRACE_CONTEXT {
    TRACEHANDLE      RegistrationHandle;
    TRACEHANDLE      Logger;
    ULONGLONG        MatchAnyKeyword;
    ULONGLONG        MatchAllKeyword;
    ULONG            Flags;
    ULONG            IsEnabled;
    UCHAR            Level;
    UCHAR            Reserve;
    USHORT           EnableBitsCount;
    PULONG           EnableBitMask;
    const PULONGLONG EnableKeyWords;
    const PUCHAR     EnableLevel;
} MCGEN_TRACE_CONTEXT, *PMCGEN_TRACE_CONTEXT;

typedef struct _RTL_BALANCED_NODE {
    union {
      struct _RTL_BALANCED_NODE *Children[2];
      struct {
        struct _RTL_BALANCED_NODE *Left;
        struct _RTL_BALANCED_NODE *Right;
      };
    };
    union {
      UCHAR     Red:1;
      UCHAR     Balance:2;
      ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef NTSTATUS (*PETWENABLECALLBACK) (
  LPCGUID                  SourceId,
  ULONG                    ControlCode,
  UCHAR                    Level,
  ULONGLONG                MatchAnyKeyword,
  ULONGLONG                MatchAllKeyword,
  PEVENT_FILTER_DESCRIPTOR FilterData,
  PVOID                    CallbackContext);

typedef struct _RTL_RB_TREE {
    struct _RTL_BALANCED_NODE* Root;
    union {
      UCHAR Encoded:1; /* bit position: 0 */
      struct _RTL_BALANCED_NODE* Min;
    };
} RTL_RB_TREE, *PRTL_RB_TREE;
    
typedef struct _ETW_USER_REG_ENTRY {
    RTL_BALANCED_NODE   RegList;           // List of registration entries
    ULONG64             Padding1;
    GUID                ProviderId;        // GUID to identify Provider
    PETWENABLECALLBACK  Callback;          // Callback function executed in response to NtControlTrace
    PVOID               CallbackContext;   // Optional context
    SRWLOCK             RegLock;           // 
    SRWLOCK             NodeLock;          // 
    HANDLE              Thread;            // Handle of thread for callback
    HANDLE              ReplyHandle;       // Used to communicate with the kernel via NtTraceEvent
    USHORT              RegIndex;          // Index in EtwpRegistrationTable
    USHORT              RegType;           // 14th bit indicates a private
    ULONG64             Unknown[19];
} ETW_USER_REG_ENTRY, *PETW_USER_REG_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif

  BSTR etw_id2name(OLECHAR *id);
  BOOL etw_disable(HANDLE hp, PRTL_BALANCED_NODE node, USHORT index); 
  VOID etw_reg_info(HANDLE hp, PRTL_BALANCED_NODE node, PETW_USER_REG_ENTRY re, int tabs);
  VOID etw_dump_nodes(HANDLE hp, PRTL_BALANCED_NODE node, PWCHAR dll, int opt, int tabs);
  VOID etw_search_process(HANDLE hp, PPROCESSENTRY32 pe32, LPVOID etw, PWCHAR dll, int opt);
  LPVOID etw_get_table_va(VOID);
  PRTL_BALANCED_NODE etw_get_reg(HANDLE hp, LPVOID etw, PWCHAR prov, PETW_USER_REG_ENTRY re); 
  BOOL etw_inject(DWORD pid, PWCHAR path, PWCHAR prov);
  BOOL etw_disable(HANDLE hp, PRTL_BALANCED_NODE node, USHORT index);
  VOID etw_search_system(DWORD pid, PWCHAR dll, PWCHAR prov, int opt);

#ifdef __cplusplus
}
#endif
    
#endif
