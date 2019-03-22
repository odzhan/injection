
<h2>Fun with the Service Control Handler</h2>

<p>This tool was originally written for a CTF many years ago for the purpose of stopping the windows event logger. Since the event logger refused to accept SERVICE_CONTROL_STOP, the only option was to terminate the host process or at least the threads running the service.</p>

<h3>Internal Dispatch Entry</h3>

<p>Every Windows service has a "control handler" to receive control codes from the operating system. Depending on what the service is willing to accept, the more common control codes for a service are interrogate, start, stop, pause or resume. A pointer to the Control Handler is stored in a data structure on the heap that Microsoft refers to as an "Internal Dispatch Entry" (IDE).</p>

<p>The following structure is supported by versions of windows 7.</p>

<pre>
typedef struct _INTERNAL_DISPATCH_ENTRY {
    LPWSTR                  ServiceName;
    LPWSTR                  ServiceRealName;
    LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
    LPHANDLER_FUNCTION_EX   ControlHandler;
    HANDLE                  StatusHandle;
    DWORD                   ServiceFlags;
    DWORD                   Tag;
    HANDLE                  MainThreadHandle;
    DWORD                   dwReserved;
} INTERNAL_DISPATCH_ENTRY, *PINTERNAL_DISPATCH_ENTRY;
</pre>

<p>The following structure is supported by versions of windows 10.</p>

<pre>
typedef struct _INTERNAL_DISPATCH_ENTRY {
    LPWSTR                  ServiceName;
    LPWSTR                  ServiceRealName;
    LPWSTR                  ServiceName2;       // Windows 10
    LPSERVICE_MAIN_FUNCTION ServiceStartRoutine;
    LPHANDLER_FUNCTION_EX   ControlHandler;
    HANDLE                  StatusHandle;
    DWORD64                 ServiceFlags;        // 64-bit on windows 10
    DWORD64                 Tag;
    HANDLE                  MainThreadHandle;
    DWORD64                 dwReserved;
    DWORD64                 dwReserved2;
} INTERNAL_DISPATCH_ENTRY, *PINTERNAL_DISPATCH_ENTRY;
</pre>

<p>To find valid entries consists of searching all writeable areas of memory for a process hosting a service.</p>

<h3>Stopping a service</h3>

<p>Once a valid service IDE has been found, we can stop the service by executing the ControlHandler code using a remote thread and passing SERVICE_CONTROL_STOP as the parameter. For more information, refer to the StopService() function.</p>

<h3>Process injection</h3>

<p>It's also possible to overwrite the ControlHandler value with a a pointer to other code and forcing the service to execute via the ControlService API and SERVICE_CONTROL_INTERROGATE code. This requires setting the ServiceFlags field to SERVICE_CONTROL_INTERROGATE. For more information, refer to the SvcCtrlInject() function.</p>

<h3>When things go wrong</h3>

<p>The service names in an IDE don't always correspond with the name in the service database. Take for example the following entry.</p>

<pre>
SERVICE_NAME: WpnUserService_2e777
DISPLAY_NAME: Windows Push Notifications User Service_2e777
        TYPE               : e0  USER_SHARE_PROCESS INSTANCE
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_PRESHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
</pre>

<p>This tool will find the host process for "WpnUserService_2e777" but will not find a valid IDE. An additional option is available (-l) to list all valid IDEs found in the host process. Using the same service again with -l</p>
  
<pre>
ServiceName         : 0000024667405FD0 (WpnUserService)
ServiceRealName     : 0000024667405FD0 (WpnUserService)
ServiceStartRoutine : 00007FF790652F80
ControlHandler      : 00007FFF9422D3C0
StatusHandle        : 00000246674155C0
ServiceFlags        : 0000000000000002
Tag                 : 00007FFF942381A0
MainThreadHandle    : 0000000000000111 (273)

ServiceName         : 0000024667406010 (UnistoreSvc)
ServiceRealName     : 0000024667406010 (UnistoreSvc)
ServiceStartRoutine : 00007FF790652F80
ControlHandler      : 00007FFF96FBF0D0
StatusHandle        : 00000246698FF100
ServiceFlags        : 0000000000000002
Tag                 : 00007FFF97008580
MainThreadHandle    : 000000000000010F (271)

ServiceName         : 0000024667406028 (PimIndexMaintenanceSvc)
ServiceRealName     : 0000024667406028 (PimIndexMaintenanceSvc)
ServiceStartRoutine : 00007FF790652F80
ControlHandler      : 00007FFF96E5DFD0
StatusHandle        : 0000024669C54440
ServiceFlags        : 0000000000000002
Tag                 : 00007FFF96E6AB00
MainThreadHandle    : 000000000000010D (269)

ServiceName         : 0000024667406056 (CDPUserSvc)
ServiceRealName     : 0000024667406056 (CDPUserSvc)
ServiceStartRoutine : 00007FF790652F80
ControlHandler      : 00007FFF9426FAD0
StatusHandle        : 0000024667415760
ServiceFlags        : 0000000000000002
Tag                 : 0000024667426060
MainThreadHandle    : 0000000000000108 (264)

ServiceName         : 000002466740606C (UserDataSvc)
ServiceRealName     : 000002466740606C (UserDataSvc)
ServiceStartRoutine : 00007FF790652F80
ControlHandler      : 00007FFF8501F4C0
StatusHandle        : 00000246698FF180
ServiceFlags        : 0000000000000002
Tag                 : 00007FFF85078500
MainThreadHandle    : 0000000000000110 (272)

ServiceName         : 0000024667406084 (OneSyncSvc)
ServiceRealName     : 0000024667406084 (OneSyncSvc)
ServiceStartRoutine : 00007FF790652F80
ControlHandler      : 00007FFF8498BE90
StatusHandle        : 0000024669841A40
ServiceFlags        : 0000000000000002
Tag                 : 00007FFF849AAFB0
MainThreadHandle    : 000000000000010C (268)
</pre>

<p>"WpnUserService" is the service name stored in the IDE, but the service database uses "WpnUserService_2e777". An additional option can be used to target a specific thread. Pass the decimal value of MainThreadHandle to the tool along with the database service name and it will locate the correct entry.</p>
  
  
  
  
