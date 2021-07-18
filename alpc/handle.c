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
  
#include "../NTlib/util.h"

VOID PrintHandle(DWORD pid, PWCHAR type, PWCHAR name, PWCHAR file) {
    wprintf(L"%-30s:[%5i] %-20s : %s\n", 
        pid2name(pid), pid, type, name==NULL ? file : name);
}
#define MAX_BUFSIZ 8192

VOID ListProcessHandles(DWORD pid, PWCHAR objType, BOOL bNameRequired) {    
    ULONG                      len=0, total=0;
    NTSTATUS                   status;
    LPVOID                     list=NULL;    
    DWORD                      i;
    HANDLE                     hp, hObject;
    OBJECT_BASIC_INFORMATION   obi;
    POBJECT_TYPE_INFORMATION   t;
    POBJECT_NAME_INFORMATION   n;
    PSYSTEM_HANDLE_INFORMATION hl;
    WCHAR                      filename[MAX_PATH];
    PWCHAR                     type, name, file;
    
    // query until we have list of handles
    for(len=MAX_BUFSIZ;;len+=MAX_BUFSIZ) {
      list = xmalloc(len);
      status = NtQuerySystemInformation(
          SystemHandleInformation, list, len, &total);
      // break from loop if ok    
      if(NT_SUCCESS(status)) break;
      // free list and continues
      xfree(list);   
    }
    
    hl = (PSYSTEM_HANDLE_INFORMATION)list;
    t  = (POBJECT_TYPE_INFORMATION)xmalloc(MAX_BUFSIZ);
    n  = (POBJECT_NAME_INFORMATION)xmalloc(MAX_BUFSIZ);

    // for each handle
    for(i=0; i<hl->NumberOfHandles; i++) {
      // skip these to avoid hanging process
      if((hl->Handles[i].GrantedAccess == 0x0012019f) || 
         (hl->Handles[i].GrantedAccess == 0x001a019f) || 
         (hl->Handles[i].GrantedAccess == 0x00120189) || 
         (hl->Handles[i].GrantedAccess == 0x00100000)) {
        continue;
      }

      type=NULL; name=NULL; file=NULL;
      // does user want to filter out process?
      if(pid != 0 && (hl->Handles[i].UniqueProcessId != pid)) {
        continue;
      }
      // open the process to duplicate handle. continue on error
      hp = OpenProcess(PROCESS_DUP_HANDLE, 
        FALSE, hl->Handles[i].UniqueProcessId);
      if(hp==NULL) {
        continue;
      }

      // duplicate the handle object
      status = NtDuplicateObject(
            hp, (HANDLE)hl->Handles[i].HandleValue, 
            GetCurrentProcess(), &hObject, 0, 0, 0);
            
      CloseHandle(hp);
      // continue with next if we failed
      if(!NT_SUCCESS(status)) {
        continue;
      }
      // query basic info about object
      status = NtQueryObject(hObject, 
            ObjectBasicInformation, &obi, 
            sizeof(obi), &len);
            
      if(NT_SUCCESS(status)) {
        // query the type
        status = NtQueryObject(hObject, 
              ObjectTypeInformation, t, 
              MAX_BUFSIZ, NULL);
                  
        // okay? store the type
        if (NT_SUCCESS(status)) {
          type = t->TypeName.Buffer;
        }
        // if there's a name for this object
        if(obi.NameInfoSize != 0) {
          // query the name
          status = NtQueryObject(hObject, 
                ObjectNameInformation, n, 
                MAX_BUFSIZ, NULL);
          // okay? store the name
          if(NT_SUCCESS(status)) {
            name = n->Name.Buffer;
          }
        } else {
          // try get the filename
          ZeroMemory(filename, ARRAYSIZE(filename));
          len=GetFinalPathNameByHandle(hObject, 
            filename, MAX_PATH, VOLUME_NAME_NT);
          // okay? store the filename
          if(len!=0) {
            file = filename;
          }
        }
      }
      // close handle object
      NtClose(hObject); 
      // skip it if we didn't get a name for this object
      if(bNameRequired) {
        if(name==NULL && file==NULL) continue;
      }
      // is this the right object type?
      if(objType!=NULL && (StrStrI(type, objType)==NULL)) continue;
      PrintHandle(hl->Handles[i].UniqueProcessId, type, name, file);
    }
    xfree(t);
    xfree(n);
    // free list of handles
    xfree(list);
}

void usage(void) {
    wprintf(L"\nusage: handle <id | name> /t <type> /n\n");
    wprintf(L"    /t <type> : Type of objects to find. i.e: section, event, mutant, alpc, file.\n");
    wprintf(L"    /n        : Don't require name for object.\n\n");
    exit(0);
}

int main(void) {
    DWORD   pid=0;
    PWCHAR  *argv, type=NULL,process=NULL;
    BOOL    bName=TRUE; // skip objects with no name
    int     i, argc;
    wchar_t opt;
    
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    for(i=1;i<argc;i++) {
      if((argv[i][0]==L'/') || (argv[i][0]==L'-')) {
        opt=argv[i][1];
        switch(opt) {
          // specify type of object
          case L't':
          case L'T':
            type=argv[++i];
            break;
          // don't require a name for object
          case L'n':
          case L'N':
            bName=FALSE;
            break;
          case L'?':
          case L'h':
          case L'H':
          default:
            usage();
            break;
        }
      } else {
        process=argv[i];
      }
    }
    // if the user provides parameter
    // assume it's a string name for process or process id
    if(process!=NULL) {
      pid=name2pid(process);
      if(pid==0) pid=wcstoull(process, NULL, 10);
      if(pid==0) { 
        usage();
      }
    }
    SetPrivilege(SE_DEBUG_NAME, TRUE);
    ListProcessHandles(pid, type, bName);
    return 0;
}