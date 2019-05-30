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

#ifndef WNF_H
#define WNF_H

#define WNF_STATE_KEY                0x41C64E6DA3BC0074

// kernel-mode structures
#define WNF_NODE_SCOPE_MAP           0x901
#define WNF_NODE_SCOPE_INSTANCE      0x902
#define WNF_NODE_NAME_INSTANCE       0x903
#define WNF_NODE_STATE_DATA          0x904
#define WNF_NODE_SUBSCRIBE_INSTANCE  0x905
#define WNF_NODE_PROCESS_CONTEXT     0x906

// user-mode structures
#define WNF_NODE_SUBSCRIPTION_TABLE  0x911
#define WNF_NODE_NAME_SUBSCRIPTION   0x912
#define WNF_NODE_SERIALIZATION_GROUP 0x913
#define WNF_NODE_USER_SUBSCRIPTION   0x914

typedef enum _WNF_STATE_NAME_LIFETIME {
    WnfWellKnownStateName  = 0x0,
    WnfPermanentStateName  = 0x1,
    WnfPersistentStateName = 0x2,
    WnfTemporaryStateName  = 0x3
} WNF_STATE_NAME_LIFETIME;

typedef enum _WNF_DATA_SCOPE {
    WnfDataScopeSystem  = 0x0,
    WnfDataScopeSession = 0x1,
    WnfDataScopeUser    = 0x2,
    WnfDataScopeProcess = 0x3,
    WnfDataScopeMachine = 0x4
} WNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_INFORMATION {
    WnfInfoStateNameExist     = 0x0,
    WnfInfoSubscribersPresent = 0x1,
    WnfInfoIsQuiescent        = 0x2
} WNF_STATE_NAME_INFORMATION;

typedef struct _WNF_STATE_NAME_INTERNAL {
    ULONG64 Version       :4;
    ULONG64 NameLifetime  :2;
    ULONG64 DataScope     :4;
    ULONG64 PermanentData :1;
    ULONG64 Unique        :53;
} WNF_STATE_NAME_INTERNAL, *PWNF_STATE_NAME_INTERNAL;

typedef ULONG LOGICAL;
typedef ULONG *PLOGICAL;

typedef struct _WNF_STATE_NAME {
    ULONG                             Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef const struct _WNF_STATE_NAME* PCWNF_STATE_NAME;

typedef struct _WNF_TYPE_ID {
    GUID                              TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef struct _WNF_DELIVERY_DESCRIPTOR {
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME                    StateName;
    WNF_CHANGE_STAMP                  ChangeStamp;
    ULONG                             StateDataSize;
    ULONG                             EventMask;
    WNF_TYPE_ID                       TypeId;
    ULONG                             StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, *PWNF_DELIVERY_DESCRIPTOR;

typedef struct _WNF_CONTEXT_HEADER {
    USHORT                            NodeTypeCode;
    USHORT                            NodeByteSize;
} WNF_CONTEXT_HEADER, *PWNF_CONTEXT_HEADER;

typedef struct _WNF_SUBSCRIPTION_TABLE {
    WNF_CONTEXT_HEADER                Header;
    SRWLOCK                           NamesTableLock;
    LIST_ENTRY                        NamesTableEntry;
    LIST_ENTRY                        SerializationGroupListHead;
    SRWLOCK                           SerializationGroupLock;
    DWORD                             Unknown1[2];
    DWORD                             SubscribedEventSet;
    DWORD                             Unknown2[2];
    PTP_TIMER                         Timer;
    ULONG64                           TimerDueTime;
} WNF_SUBSCRIPTION_TABLE, *PWNF_SUBSCRIPTION_TABLE;

typedef struct _WNF_NAME_SUBSCRIPTION {
    WNF_CONTEXT_HEADER                Header;
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME_INTERNAL           StateName;
    WNF_CHANGE_STAMP                  CurrentChangeStamp;
    LIST_ENTRY                        NamesTableEntry;
    PWNF_TYPE_ID                      TypeId;
    SRWLOCK                           SubscriptionLock;
    LIST_ENTRY                        SubscriptionsListHead;
    ULONG                             NormalDeliverySubscriptions;
    ULONG                             NotificationTypeCount[5];
    PWNF_DELIVERY_DESCRIPTOR          RetryDescriptor;
    ULONG                             DeliveryState;
    ULONG64                           ReliableRetryTime;
} WNF_NAME_SUBSCRIPTION, *PWNF_NAME_SUBSCRIPTION;

typedef struct _WNF_SERIALIZATION_GROUP {
    WNF_CONTEXT_HEADER                Header;
    ULONG                             GroupId;
    LIST_ENTRY                        SerializationGroupList;
    ULONG64                           SerializationGroupValue;
    ULONG64                           SerializationGroupMemberCount;
} WNF_SERIALIZATION_GROUP, *PWNF_SERIALIZATION_GROUP;

typedef NTSTATUS (*PWNF_USER_CALLBACK) (
    WNF_STATE_NAME                    StateName,
    WNF_CHANGE_STAMP                  ChangeStamp,
    PWNF_TYPE_ID                      TypeId,
    PVOID                             CallbackContext,
    PVOID                             Buffer,
    ULONG                             BufferSize);
    
typedef struct _WNF_USER_SUBSCRIPTION {
    WNF_CONTEXT_HEADER                Header;
    LIST_ENTRY                        SubscriptionsListEntry;
    PWNF_NAME_SUBSCRIPTION            NameSubscription;
    PWNF_USER_CALLBACK                Callback;
    PVOID                             CallbackContext;
    ULONG64                           SubProcessTag;
    ULONG                             CurrentChangeStamp;
    ULONG                             DeliveryOptions;
    ULONG                             SubscribedEventSet;
    PWNF_SERIALIZATION_GROUP          SerializationGroup;
    ULONG                             UserSubscriptionCount;
    ULONG64                           Unknown[10];
} WNF_USER_SUBSCRIPTION, *PWNF_USER_SUBSCRIPTION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateWnfStateName(
    _Out_ PWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_LIFETIME NameLifetime,
    _In_ WNF_DATA_SCOPE DataScope,
    _In_ BOOLEAN PersistData,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_ ULONG MaximumStateSize,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteWnfStateName(
    _In_ PCWNF_STATE_NAME StateName
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUpdateWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_reads_bytes_opt_(Length) const VOID *Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID *ExplicitScope,
    _In_ WNF_CHANGE_STAMP MatchingChangeStamp,
    _In_ LOGICAL CheckStamp
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ const VOID *ExplicitScope
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryWnfStateData(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ const VOID *ExplicitScope,
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _Out_writes_bytes_to_opt_(*BufferSize, *BufferSize) PVOID Buffer,
    _Inout_ PULONG BufferSize
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryWnfStateNameInformation(
    _In_ PCWNF_STATE_NAME StateName,
    _In_ WNF_STATE_NAME_INFORMATION NameInfoClass,
    _In_opt_ const VOID *ExplicitScope,
    _Out_writes_bytes_(InfoBufferSize) PVOID InfoBuffer,
    _In_ ULONG InfoBufferSize
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSubscribeWnfStateChange(
    _In_ PCWNF_STATE_NAME StateName,
    _In_opt_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ ULONG EventMask,
    _Out_opt_ PULONG64 SubscriptionId
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnsubscribeWnfStateChange(
    _In_ PCWNF_STATE_NAME StateName
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetCompleteWnfStateSubscription(
    _In_opt_ PWNF_STATE_NAME OldDescriptorStateName,
    _In_opt_ ULONG64 *OldSubscriptionId,
    _In_opt_ ULONG OldDescriptorEventMask,
    _In_opt_ ULONG OldDescriptorStatus,
    _Out_writes_bytes_(DescriptorSize) PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    _In_ ULONG DescriptorSize
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetWnfProcessNotificationEvent(
    _In_ HANDLE NotificationEvent
    );


typedef struct _CT_CONTEXT {
    PTP_WORK                          WorkItem;
    PWNF_USER_SUBSCRIPTION            Subscription;
    HANDLE                            hEvent;
} CT_CONTEXT, *PCT_CONTEXT;

typedef struct _tagWnfName {
    const char* Name;
    ULONG64     StateName;
} WnfName;

#endif