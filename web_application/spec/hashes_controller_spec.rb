require 'rails_helper'
require 'webmock/rspec'

RSpec.describe HashesController, type: :controller do
  describe 'POST #create' do
    context 'with a valid input hash' do
      let(:input_hash) { '5751d5a9c55c4ba34651c183c72215263ec50a8c9162dce90cea5523d8dd42ec' }

      before do
        stub_request(:get, "https://www.virustotal.com/api/v3/search?query=5751d5a9c55c4ba34651c183c72215263ec50a8c9162dce90cea5523d8dd42ec").
         with(
           headers: {
          'Accept'=>'application/json',
          'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Host'=>'www.virustotal.com',
          'User-Agent'=>'Ruby',
          'X-Apikey'=>'06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
           }).
         to_return(status: 200, body: '{
          "data": [
              {
                  "attributes": {
                      "type_description": "Win32 EXE",
                      "tlsh": "T10206D071E522453AF2A386778D7F3E2E693823739B03A4DB91541D9518722D2BF3260F",
                      "vhash": "036066655d17656562c8zafbz13z2071ze4z187z",
                      "type_tags": [
                          "executable",
                          "windows",
                          "win32",
                          "pe",
                          "peexe"
                      ],
                      "crowdsourced_yara_results": [
                          {
                              "description": "Detects executables packed with VMProtect.",
                              "source": "https://github.com/ditekshen/detection",
                              "author": "ditekSHen",
                              "ruleset_name": "indicator_packed",
                              "rule_name": "INDICATOR_EXE_Packed_VMProtect",
                              "ruleset_id": "00c291ca7f"
                          }
                      ],
                      "creation_date": 29882,
                      "names": [
                          "432dc849a124afef70762105bf935eda.virus"
                      ],
                      "signature_info": {
                          "x509": [
                              {
                                  "name": "VeriSign Class 3 Public Primary Certification Authority - G5",
                                  "algorithm": "sha1RSA",
                                  "valid from": "2011-02-22 19:25:17",
                                  "valid to": "2021-02-22 19:35:17",
                                  "serial number": "61 19 93 E4 00 00 00 00 00 1C",
                                  "cert issuer": "Microsoft Code Verification Root",
                                  "thumbprint": "57534CCC33914C41F70E2CBB2103A1DB18817D8B"
                              },
                              {
                                  "name": "Hubei Century Network Technology Co.,Ltd",
                                  "algorithm": "sha1RSA",
                                  "valid from": "2013-09-05 00:00:00",
                                  "valid to": "2016-12-04 23:59:59",
                                  "serial number": "50 9B 10 4F 8E 11 BE 5F E6 B7 63 31 63 64 EF 5A",
                                  "cert issuer": "VeriSign Class 3 Code Signing 2010 CA",
                                  "thumbprint": "3C7A8A8E37314213EF7B6AA9D71B5CCC9B57BB86",
                                  "valid_usage": "Code Signing"
                              }
                          ]
                      },
                      "last_modification_date": 1687965430,
                      "type_tag": "peexe",
                      "times_submitted": 3,
                      "total_votes": {
                          "harmless": 1,
                          "malicious": 0
                      },
                      "size": 3686384,
                      "popular_threat_classification": {
                          "suggested_threat_label": "trojan.agentb/doina",
                          "popular_threat_category": [
                              {
                                  "count": 23,
                                  "value": "trojan"
                              }
                          ],
                          "popular_threat_name": [
                              {
                                  "count": 8,
                                  "value": "agentb"
                              },
                              {
                                  "count": 6,
                                  "value": "doina"
                              },
                              {
                                  "count": 2,
                                  "value": "shellcode"
                              }
                          ]
                      },
                      "authentihash": "6089f26a1084e6bbb70ce524e47ccd7e6b0a4088d15ac48d7044f6874841b4a0",
                      "detectiteasy": {
                          "filetype": "PE32",
                          "values": [
                              {
                                  "info": "GUI32",
                                  "version": "10.0",
                                  "type": "Linker",
                                  "name": "Microsoft Linker"
                              }
                          ]
                      },
                      "last_submission_date": 1642581163,
                      "meaningful_name": "432dc849a124afef70762105bf935eda.virus",
                      "trid": [
                          {
                              "file_type": "Win32 Executable MS Visual C++ (generic)",
                              "probability": 36.9
                          },
                          {
                              "file_type": "Microsoft Visual C++ compiled executable (generic)",
                              "probability": 19.5
                          },
                          {
                              "file_type": "Win64 Executable (generic)",
                              "probability": 12.4
                          },
                          {
                              "file_type": "Win32 Dynamic Link Library (generic)",
                              "probability": 7.7
                          },
                          {
                              "file_type": "Win16 NE executable (generic)",
                              "probability": 5.9
                          }
                      ],
                      "sandbox_verdicts": {
                          "C2AE": {
                              "category": "suspicious",
                              "confidence": 50,
                              "sandbox_name": "C2AE",
                              "malware_classification": [
                                  "GREYWARE"
                              ],
                              "malware_names": [
                                  "Eyoo"
                              ]
                          }
                      },
                      "sha256": "5751d5a9c55c4ba34651c183c72215263ec50a8c9162dce90cea5523d8dd42ec",
                      "type_extension": "exe",
                      "tags": [
                          "peninja",
                          "peexe",
                          "spreader",
                          "overlay"
                      ],
                      "last_analysis_date": 1687793971,
                      "unique_sources": 3,
                      "first_submission_date": 1605779112,
                      "sha1": "ccdf8c8ca4bf8fb30813f02555e59373e8301ca1",
                      "ssdeep": "49152:89yiCJ5rFwnANZGEXep+9TxFegOSDAmosh3ANkTTlSfg4HzZ4DGu4fg:zJ5rFwnApezgOS9V3AMz4HzKDGlo",
                      "packers": {
                          "PEiD": "PENinja",
                          "Cyren": "rsrc"
                      },
                      "md5": "432dc849a124afef70762105bf935eda",
                      "pe_info": {
                          "resource_details": [
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 6.787815570831299,
                                  "chi2": 1385242.5,
                                  "filetype": "DOS EXE",
                                  "sha256": "784261d2295d6ae5d23ee194cd79e20828ed80208c4d6c1c8992585a90cc1f9e",
                                  "type": "EYMC32"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 6.903674125671387,
                                  "chi2": 1480631.62,
                                  "filetype": "DOS EXE",
                                  "sha256": "7e739642f6fe43cf6742c7da1214da6492dc01c619ab310152969f2a99d1cd84",
                                  "type": "EYMC64"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 4.698215961456299,
                                  "chi2": 202353.61,
                                  "filetype": "unknown",
                                  "sha256": "771151320d4b0311e73b79f6dda2636d96350b3142dcc89f089268b19c1a3ce3",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 4.585202693939209,
                                  "chi2": 134679.41,
                                  "filetype": "unknown",
                                  "sha256": "135ae96749bbf6f1f92df6311d5f4cac5933b27c9887a1bd0977037da44b3f64",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 3.4661428928375244,
                                  "chi2": 176134.53,
                                  "filetype": "unknown",
                                  "sha256": "76ba607ff1d81af25110f4e6bd3e2b556ae66b5f73008a1797f42b17cb500b84",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 2.8078136444091797,
                                  "chi2": 179500.55,
                                  "filetype": "unknown",
                                  "sha256": "1e1439228c6df6519112b67c2f192e0fa6e8105701afb44aaa4691a9a4b76d45",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 4.793693542480469,
                                  "chi2": 494082.56,
                                  "filetype": "unknown",
                                  "sha256": "504bd7f3d9d3e239dac6eb474c5a76e99e65594d94dbd8fe814c8717f34a91f6",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 4.950520038604736,
                                  "chi2": 188634.8,
                                  "filetype": "unknown",
                                  "sha256": "127cd61a68beaa3fbdb94b4bf10b1f8f6a37dd2d4474ae29ca3880122219d1b2",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 5.390736103057861,
                                  "chi2": 89190.29,
                                  "filetype": "unknown",
                                  "sha256": "58a21130575111d0722bc26500eb54e82b5a60b54136df3b3243588a702c2d4f",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 4.494389057159424,
                                  "chi2": 53517.5,
                                  "filetype": "unknown",
                                  "sha256": "2c98df01432ebf72d824345fc2efaa7ba0a6f5a57d87b3bcf01571111ab93f85",
                                  "type": "RT_ICON"
                              },
                              {
                                  "lang": "CHINESE SIMPLIFIED",
                                  "entropy": 2.8581185340881348,
                                  "chi2": 8364.71,
                                  "filetype": "ICO",
                                  "sha256": "146e554f0d56db9a88224cd6921744fdfe1f8ee4a9e3ac79711f9ab15f9d3c7f",
                                  "type": "RT_GROUP_ICON"
                              },
                              {
                                  "lang": "ENGLISH US",
                                  "entropy": 4.795973777770996,
                                  "chi2": 3958.65,
                                  "filetype": "unknown",
                                  "sha256": "49a60be4b95b6d30da355a0c124af82b35000bce8f24f957d1c09ead47544a1e",
                                  "type": "RT_MANIFEST"
                              }
                          ],
                          "resource_types": {
                              "RT_ICON": 8,
                              "RT_GROUP_ICON": 1,
                              "RT_MANIFEST": 1,
                              "EYMC64": 1,
                              "EYMC32": 1
                          },
                          "imphash": "fcdcf4239ade4bb66e6f89d5914ca08e",
                          "overlay": {
                              "entropy": 4.8807244300842285,
                              "offset": 2234368,
                              "chi2": 92984184.0,
                              "filetype": "unknown",
                              "md5": "0f3d98a1c745e7b411a19407205db3e4",
                              "size": 1452016
                          },
                          "resource_langs": {
                              "ENGLISH US": 1,
                              "CHINESE SIMPLIFIED": 11
                          },
                          "machine_type": 332,
                          "timestamp": 29882,
                          "entry_point": 317472,
                          "sections": [
                              {
                                  "name": ".text",
                                  "chi2": 5713817.0,
                                  "virtual_address": 4096,
                                  "flags": "rx",
                                  "raw_size": 1018880,
                                  "entropy": 6.59,
                                  "virtual_size": 1018546,
                                  "md5": "5bb7d960ec9610a096655021591e6726"
                              },
                              {
                                  "name": ".rdata",
                                  "chi2": 4173968.25,
                                  "virtual_address": 1024000,
                                  "flags": "r",
                                  "raw_size": 150016,
                                  "entropy": 5.55,
                                  "virtual_size": 149970,
                                  "md5": "c84870398a772447e452e2ae42b68fc3"
                              },
                              {
                                  "name": ".data",
                                  "chi2": 4279544.5,
                                  "virtual_address": 1175552,
                                  "flags": "rw",
                                  "raw_size": 27648,
                                  "entropy": 2.24,
                                  "virtual_size": 38404,
                                  "md5": "667b32057779267fcfacbb6c6c62a6df"
                              },
                              {
                                  "name": ".cpp0",
                                  "chi2": 2040147.62,
                                  "virtual_address": 1216512,
                                  "flags": "rx",
                                  "raw_size": 591360,
                                  "entropy": 6.83,
                                  "virtual_size": 590864,
                                  "md5": "dc5fe8631b014ff264c2274e240d0d3f"
                              },
                              {
                                  "name": ".reloc",
                                  "chi2": 188685.67,
                                  "virtual_address": 1810432,
                                  "flags": "r",
                                  "raw_size": 50176,
                                  "entropy": 6.73,
                                  "virtual_size": 50052,
                                  "md5": "b1b999790753b9b0cf4b6600b870612d"
                              },
                              {
                                  "name": ".rsrc",
                                  "chi2": 3685980.0,
                                  "virtual_address": 1863680,
                                  "flags": "r",
                                  "raw_size": 395264,
                                  "entropy": 6.8,
                                  "virtual_size": 394966,
                                  "md5": "7c10466af4e40861a176e26eeec560ea"
                              }
                          ],
                          "import_list": [
                              {
                                  "library_name": "imagehlp.dll",
                                  "imported_functions": [
                                      "CheckSumMappedFile"
                                  ]
                              },
                              {
                                  "library_name": "IPHLPAPI.DLL",
                                  "imported_functions": [
                                      "GetAdaptersInfo"
                                  ]
                              },
                              {
                                  "library_name": "ADVAPI32.dll",
                                  "imported_functions": [
                                      "AdjustTokenPrivileges",
                                      "AllocateAndInitializeSid",
                                      "BuildExplicitAccessWithNameA",
                                      "ChangeServiceConfigW",
                                      "CloseServiceHandle",
                                      "ControlService",
                                      "CreateServiceA",
                                      "CreateServiceW",
                                      "DeleteService",
                                      "EnumDependentServicesA",
                                      "FreeSid",
                                      "GetKernelObjectSecurity",
                                      "GetLengthSid",
                                      "GetTokenInformation",
                                      "InitializeSecurityDescriptor",
                                      "LookupPrivilegeValueA",
                                      "LookupPrivilegeValueW",
                                      "OpenProcessToken",
                                      "OpenSCManagerA",
                                      "OpenSCManagerW",
                                      "OpenServiceA",
                                      "OpenServiceW",
                                      "QueryServiceConfigW",
                                      "QueryServiceStatus",
                                      "QueryServiceStatusEx",
                                      "RegCloseKey",
                                      "RegCreateKeyExA",
                                      "RegCreateKeyExW",
                                      "RegDeleteKeyA",
                                      "RegDeleteKeyW",
                                      "RegDeleteValueA",
                                      "RegEnumKeyExA",
                                      "RegEnumKeyW",
                                      "RegOpenKeyA",
                                      "RegOpenKeyExA",
                                      "RegOpenKeyExW",
                                      "RegQueryValueExA",
                                      "RegSetValueExA",
                                      "RegSetValueExW",
                                      "SetEntriesInAclA",
                                      "SetNamedSecurityInfoA",
                                      "SetSecurityDescriptorDacl",
                                      "StartServiceA",
                                      "StartServiceW"
                                  ]
                              },
                              {
                                  "library_name": "KERNEL32.dll",
                                  "imported_functions": [
                                      "AddVectoredExceptionHandler",
                                      "CloseHandle",
                                      "CompareStringW",
                                      "CreateDirectoryA",
                                      "CreateEventA",
                                      "CreateEventW",
                                      "CreateFileA",
                                      "CreateFileMappingA",
                                      "CreateFileMappingW",
                                      "CreateFileW",
                                      "CreateMutexA",
                                      "CreateMutexW",
                                      "CreateProcessA",
                                      "CreateProcessW",
                                      "CreateRemoteThread",
                                      "CreateThread",
                                      "CreateToolhelp32Snapshot",
                                      "DecodePointer",
                                      "DeleteCriticalSection",
                                      "DeleteFileA",
                                      "DeviceIoControl",
                                      "DuplicateHandle",
                                      "EncodePointer",
                                      "EnterCriticalSection",
                                      "ExitProcess",
                                      "ExitThread",
                                      "ExpandEnvironmentStringsA",
                                      "FileTimeToLocalFileTime",
                                      "FileTimeToSystemTime",
                                      "FindClose",
                                      "FindFirstFileExA",
                                      "FindResourceA",
                                      "FlushFileBuffers",
                                      "FlushInstructionCache",
                                      "FlushViewOfFile",
                                      "FormatMessageA",
                                      "FreeEnvironmentStringsW",
                                      "FreeLibrary",
                                      "FreeResource",
                                      "GetACP",
                                      "GetCommandLineA",
                                      "GetComputerNameA",
                                      "GetConsoleCP",
                                      "GetConsoleMode",
                                      "GetCPInfo",
                                      "GetCurrentDirectoryA",
                                      "GetCurrentDirectoryW",
                                      "GetCurrentProcess",
                                      "GetCurrentProcessId",
                                      "GetCurrentThread",
                                      "GetCurrentThreadId",
                                      "GetDriveTypeA",
                                      "GetDriveTypeW",
                                      "GetEnvironmentStringsW",
                                      "GetEnvironmentVariableA",
                                      "GetExitCodeThread",
                                      "GetFileAttributesA",
                                      "GetFileAttributesW",
                                      "GetFileInformationByHandle",
                                      "GetFileSize",
                                      "GetFileType",
                                      "GetFullPathNameA",
                                      "GetLastError",
                                      "GetLocalTime",
                                      "GetModuleFileNameA",
                                      "GetModuleFileNameW",
                                      "GetModuleHandleA",
                                      "GetModuleHandleW",
                                      "GetOEMCP",
                                      "GetPrivateProfileStringA",
                                      "GetProcAddress",
                                      "GetProcessHeap",
                                      "GetProcessTimes",
                                      "GetStartupInfoW",
                                      "GetStdHandle",
                                      "GetStringTypeW",
                                      "GetSystemDirectoryA",
                                      "GetSystemDirectoryW",
                                      "GetSystemInfo",
                                      "GetSystemTime",
                                      "GetSystemTimeAsFileTime",
                                      "GetSystemWow64DirectoryA",
                                      "GetThreadContext",
                                      "GetTickCount",
                                      "GetTimeZoneInformation",
                                      "GetVersion",
                                      "GetVersionExW",
                                      "GetWindowsDirectoryW",
                                      "HeapAlloc",
                                      "HeapCreate",
                                      "HeapFree",
                                      "HeapReAlloc",
                                      "HeapSetInformation",
                                      "HeapSize",
                                      "InitializeCriticalSection",
                                      "InitializeCriticalSectionAndSpinCount",
                                      "InterlockedCompareExchange",
                                      "InterlockedDecrement",
                                      "InterlockedExchange",
                                      "InterlockedIncrement",
                                      "IsBadReadPtr",
                                      "IsDebuggerPresent",
                                      "IsProcessorFeaturePresent",
                                      "IsValidCodePage",
                                      "LCMapStringW",
                                      "LeaveCriticalSection",
                                      "LoadLibraryA",
                                      "LoadLibraryW",
                                      "LoadResource",
                                      "LocalAlloc",
                                      "LocalFileTimeToFileTime",
                                      "LocalFree",
                                      "LockResource",
                                      "lstrcatA",
                                      "lstrcmpiA",
                                      "lstrcpyA",
                                      "lstrcpyW",
                                      "lstrlenA",
                                      "lstrlenW",
                                      "MapViewOfFile",
                                      "MoveFileA",
                                      "MultiByteToWideChar",
                                      "OpenEventW",
                                      "OpenFileMappingA",
                                      "OpenFileMappingW",
                                      "OpenMutexW",
                                      "OpenProcess",
                                      "OutputDebugStringA",
                                      "PeekNamedPipe",
                                      "Process32First",
                                      "Process32Next",
                                      "QueryPerformanceCounter",
                                      "RaiseException",
                                      "ReadFile",
                                      "ReadProcessMemory",
                                      "ReleaseMutex",
                                      "ResetEvent",
                                      "ResumeThread",
                                      "RtlUnwind",
                                      "SetEndOfFile",
                                      "SetEnvironmentVariableA",
                                      "SetFilePointer",
                                      "SetFileTime",
                                      "SetHandleCount",
                                      "SetLastError",
                                      "SetNamedPipeHandleState",
                                      "SetStdHandle",
                                      "SetUnhandledExceptionFilter",
                                      "SizeofResource",
                                      "Sleep",
                                      "SleepEx",
                                      "SystemTimeToFileTime",
                                      "TerminateProcess",
                                      "TlsAlloc",
                                      "TlsFree",
                                      "TlsGetValue",
                                      "TlsSetValue",
                                      "UnhandledExceptionFilter",
                                      "UnmapViewOfFile",
                                      "VirtualAlloc",
                                      "VirtualAllocEx",
                                      "VirtualFree",
                                      "VirtualFreeEx",
                                      "VirtualProtect",
                                      "VirtualProtectEx",
                                      "VirtualQuery",
                                      "VirtualQueryEx",
                                      "WaitForSingleObject",
                                      "WaitNamedPipeA",
                                      "WaitNamedPipeW",
                                      "WideCharToMultiByte",
                                      "WinExec",
                                      "WriteConsoleW",
                                      "WriteFile",
                                      "WriteProcessMemory"
                                  ]
                              },
                              {
                                  "library_name": "SHELL32.dll",
                                  "imported_functions": [
                                      "ShellExecuteExA",
                                      "SHFileOperationA"
                                  ]
                              },
                              {
                                  "library_name": "PSAPI.DLL",
                                  "imported_functions": [
                                      "GetMappedFileNameA"
                                  ]
                              },
                              {
                                  "library_name": "SHLWAPI.dll",
                                  "imported_functions": [
                                      "PathAddBackslashA",
                                      "PathFileExistsA",
                                      "PathFindFileNameA",
                                      "PathIsDirectoryA",
                                      "PathIsRootA",
                                      "PathRemoveFileSpecA",
                                      "PathStripToRootA"
                                  ]
                              },
                              {
                                  "library_name": "WS2_32.dll",
                                  "imported_functions": [
                                      "__WSAFDIsSet",
                                      "bind",
                                      "closesocket",
                                      "connect",
                                      "freeaddrinfo",
                                      "getaddrinfo",
                                      "gethostbyname",
                                      "gethostname",
                                      "getpeername",
                                      "getsockname",
                                      "getsockopt",
                                      "htons",
                                      "inet_addr",
                                      "ioctlsocket",
                                      "ntohs",
                                      "recv",
                                      "select",
                                      "send",
                                      "setsockopt",
                                      "socket",
                                      "WSACleanup",
                                      "WSAGetLastError",
                                      "WSASetLastError",
                                      "WSAStartup"
                                  ]
                              },
                              {
                                  "library_name": "USER32.dll",
                                  "imported_functions": [
                                      "CharNextA",
                                      "CloseDesktop",
                                      "DispatchMessageA",
                                      "EnumWindows",
                                      "GetMessageA",
                                      "GetParent",
                                      "GetSystemMetrics",
                                      "GetThreadDesktop",
                                      "GetUserObjectInformationA",
                                      "GetWindowThreadProcessId",
                                      "OpenInputDesktop",
                                      "PeekMessageA",
                                      "TranslateMessage",
                                      "wsprintfA"
                                  ]
                              }
                          ]
                      },
                      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                      "last_analysis_stats": {
                          "harmless": 0,
                          "type-unsupported": 4,
                          "suspicious": 0,
                          "confirmed-timeout": 0,
                          "timeout": 0,
                          "failure": 0,
                          "malicious": 59,
                          "undetected": 12
                      },
                      "last_analysis_results": {
                          "Bkav": {
                              "category": "malicious",
                              "engine_name": "Bkav",
                              "engine_version": "2.0.0.1",
                              "result": "W32.AIDetectMalware",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Lionic": {
                              "category": "malicious",
                              "engine_name": "Lionic",
                              "engine_version": "7.5",
                              "result": "Trojan.Win32.Agentb.4!c",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "tehtris": {
                              "category": "undetected",
                              "engine_name": "tehtris",
                              "engine_version": "v0.1.4",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "MicroWorld-eScan": {
                              "category": "malicious",
                              "engine_name": "MicroWorld-eScan",
                              "engine_version": "14.0.409.0",
                              "result": "Gen:Variant.Doina.58003",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "FireEye": {
                              "category": "malicious",
                              "engine_name": "FireEye",
                              "engine_version": "35.24.1.0",
                              "result": "Generic.mg.432dc849a124afef",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "CAT-QuickHeal": {
                              "category": "malicious",
                              "engine_name": "CAT-QuickHeal",
                              "engine_version": "22.00",
                              "result": "Trojan.Skeeyah.14991",
                              "method": "blacklist",
                              "engine_update": "20230625"
                          },
                          "McAfee": {
                              "category": "malicious",
                              "engine_name": "McAfee",
                              "engine_version": "6.0.6.653",
                              "result": "GenericRXLJ-AF!432DC849A124",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Cylance": {
                              "category": "malicious",
                              "engine_name": "Cylance",
                              "engine_version": "2.0.0.0",
                              "result": "unsafe",
                              "method": "blacklist",
                              "engine_update": "20230607"
                          },
                          "VIPRE": {
                              "category": "malicious",
                              "engine_name": "VIPRE",
                              "engine_version": "6.0.0.35",
                              "result": "Gen:Variant.Doina.58003",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Sangfor": {
                              "category": "malicious",
                              "engine_name": "Sangfor",
                              "engine_version": "2.23.0.0",
                              "result": "Suspicious.Win32.Save.ins",
                              "method": "blacklist",
                              "engine_update": "20230625"
                          },
                          "CrowdStrike": {
                              "category": "malicious",
                              "engine_name": "CrowdStrike",
                              "engine_version": "1.0",
                              "result": "win/grayware_confidence_90% (W)",
                              "method": "blacklist",
                              "engine_update": "20220812"
                          },
                          "BitDefender": {
                              "category": "malicious",
                              "engine_name": "BitDefender",
                              "engine_version": "7.2",
                              "result": "Gen:Variant.Doina.58003",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "K7GW": {
                              "category": "malicious",
                              "engine_name": "K7GW",
                              "engine_version": "12.93.48758",
                              "result": "Unwanted-Program ( 0055e1b21 )",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "K7AntiVirus": {
                              "category": "malicious",
                              "engine_name": "K7AntiVirus",
                              "engine_version": "12.93.48759",
                              "result": "Unwanted-Program ( 0055e1b21 )",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Arcabit": {
                              "category": "malicious",
                              "engine_name": "Arcabit",
                              "engine_version": "2022.0.0.18",
                              "result": "Trojan.Doina.DE293",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Baidu": {
                              "category": "undetected",
                              "engine_name": "Baidu",
                              "engine_version": "1.0.0.2",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20190318"
                          },
                          "VirIT": {
                              "category": "undetected",
                              "engine_name": "VirIT",
                              "engine_version": "9.5.477",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Cyren": {
                              "category": "malicious",
                              "engine_name": "Cyren",
                              "engine_version": "6.5.1.2",
                              "result": "W32/Agent.ANJ.gen!Eldorado",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "SymantecMobileInsight": {
                              "category": "type-unsupported",
                              "engine_name": "SymantecMobileInsight",
                              "engine_version": "2.0",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230119"
                          },
                          "Symantec": {
                              "category": "malicious",
                              "engine_name": "Symantec",
                              "engine_version": "1.20.0.0",
                              "result": "ML.Attribute.HighConfidence",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Elastic": {
                              "category": "malicious",
                              "engine_name": "Elastic",
                              "engine_version": "4.0.95",
                              "result": "malicious (high confidence)",
                              "method": "blacklist",
                              "engine_update": "20230620"
                          },
                          "ESET-NOD32": {
                              "category": "malicious",
                              "engine_name": "ESET-NOD32",
                              "engine_version": "27471",
                              "result": "a variant of Win32/Eyoorun.D potentially unsafe",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "APEX": {
                              "category": "malicious",
                              "engine_name": "APEX",
                              "engine_version": "6.426",
                              "result": "Malicious",
                              "method": "blacklist",
                              "engine_update": "20230625"
                          },
                          "Paloalto": {
                              "category": "undetected",
                              "engine_name": "Paloalto",
                              "engine_version": "0.9.0.1003",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "ClamAV": {
                              "category": "undetected",
                              "engine_name": "ClamAV",
                              "engine_version": "1.1.0.0",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230628"
                          },
                          "Kaspersky": {
                              "category": "malicious",
                              "engine_name": "Kaspersky",
                              "engine_version": "22.0.1.28",
                              "result": "Trojan.Win32.Agentb.bqaf",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Alibaba": {
                              "category": "undetected",
                              "engine_name": "Alibaba",
                              "engine_version": "0.3.0.5",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20190527"
                          },
                          "NANO-Antivirus": {
                              "category": "malicious",
                              "engine_name": "NANO-Antivirus",
                              "engine_version": "1.0.146.25785",
                              "result": "Trojan.Win32.Eyoorun.jwobye",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "ViRobot": {
                              "category": "malicious",
                              "engine_name": "ViRobot",
                              "engine_version": "2014.3.20.0",
                              "result": "Trojan.Win.Z.Agent.3686384",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Rising": {
                              "category": "malicious",
                              "engine_name": "Rising",
                              "engine_version": "25.0.0.27",
                              "result": "Trojan.Toga!8.136D (TFE:1:QeOv4OK49HK)",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Trustlook": {
                              "category": "type-unsupported",
                              "engine_name": "Trustlook",
                              "engine_version": "1.0",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Sophos": {
                              "category": "malicious",
                              "engine_name": "Sophos",
                              "engine_version": "2.3.1.0",
                              "result": "Troj/Agent-BEUS",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "F-Secure": {
                              "category": "malicious",
                              "engine_name": "F-Secure",
                              "engine_version": "18.10.1137.128",
                              "result": "Heuristic.HEUR/AGEN.1316181",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "DrWeb": {
                              "category": "malicious",
                              "engine_name": "DrWeb",
                              "engine_version": "7.0.59.12300",
                              "result": "Trojan.MulDrop7.18312",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Zillya": {
                              "category": "malicious",
                              "engine_name": "Zillya",
                              "engine_version": "2.0.0.4900",
                              "result": "Trojan.Agent.Win32.1291924",
                              "method": "blacklist",
                              "engine_update": "20230624"
                          },
                          "TrendMicro": {
                              "category": "malicious",
                              "engine_name": "TrendMicro",
                              "engine_version": "11.0.0.1006",
                              "result": "TROJ_GEN.R002C0PFP23",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "McAfee-GW-Edition": {
                              "category": "malicious",
                              "engine_name": "McAfee-GW-Edition",
                              "engine_version": "v2021.2.0+4045",
                              "result": "BehavesLike.Win32.Trojan.wh",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Trapmine": {
                              "category": "malicious",
                              "engine_name": "Trapmine",
                              "engine_version": "4.0.14.446",
                              "result": "malicious.high.ml.score",
                              "method": "blacklist",
                              "engine_update": "20230412"
                          },
                          "CMC": {
                              "category": "undetected",
                              "engine_name": "CMC",
                              "engine_version": "2.4.2022.1",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230619"
                          },
                          "Emsisoft": {
                              "category": "malicious",
                              "engine_name": "Emsisoft",
                              "engine_version": "2022.6.0.32461",
                              "result": "Gen:Variant.Doina.58003 (B)",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "SentinelOne": {
                              "category": "malicious",
                              "engine_name": "SentinelOne",
                              "engine_version": "23.2.0.1",
                              "result": "Static AI - Malicious PE",
                              "method": "blacklist",
                              "engine_update": "20230404"
                          },
                          "Avast-Mobile": {
                              "category": "type-unsupported",
                              "engine_name": "Avast-Mobile",
                              "engine_version": "230626-00",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Jiangmin": {
                              "category": "malicious",
                              "engine_name": "Jiangmin",
                              "engine_version": "16.0.100",
                              "result": "Trojan.Agentb.aid",
                              "method": "blacklist",
                              "engine_update": "20230625"
                          },
                          "Webroot": {
                              "category": "undetected",
                              "engine_name": "Webroot",
                              "engine_version": "1.0.0.403",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Google": {
                              "category": "malicious",
                              "engine_name": "Google",
                              "engine_version": "1687791639",
                              "result": "Detected",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Avira": {
                              "category": "malicious",
                              "engine_name": "Avira",
                              "engine_version": "8.3.3.16",
                              "result": "HEUR/AGEN.1316181",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "MAX": {
                              "category": "malicious",
                              "engine_name": "MAX",
                              "engine_version": "2023.1.4.1",
                              "result": "malware (ai score=83)",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Antiy-AVL": {
                              "category": "malicious",
                              "engine_name": "Antiy-AVL",
                              "engine_version": "3.0",
                              "result": "Trojan/Win32.Agentb",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Gridinsoft": {
                              "category": "malicious",
                              "engine_name": "Gridinsoft",
                              "engine_version": "1.0.125.174",
                              "result": "Trojan.Win32.Agent.oa!s1",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Xcitium": {
                              "category": "malicious",
                              "engine_name": "Xcitium",
                              "engine_version": "35770",
                              "result": "TrojWare.Win32.MalPack.PKB@1rava1",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Microsoft": {
                              "category": "malicious",
                              "engine_name": "Microsoft",
                              "engine_version": "1.1.23050.3",
                              "result": "PUA:Win32/EyooClientSVC",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "SUPERAntiSpyware": {
                              "category": "undetected",
                              "engine_name": "SUPERAntiSpyware",
                              "engine_version": "5.6.0.1032",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230622"
                          },
                          "ZoneAlarm": {
                              "category": "malicious",
                              "engine_name": "ZoneAlarm",
                              "engine_version": "1.0",
                              "result": "Trojan.Win32.Agentb.bqaf",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "GData": {
                              "category": "malicious",
                              "engine_name": "GData",
                              "engine_version": "A:25.36097B:27.32195",
                              "result": "Win32.Trojan.PSE.160EHF6",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Cynet": {
                              "category": "malicious",
                              "engine_name": "Cynet",
                              "engine_version": "4.0.0.27",
                              "result": "Malicious (score: 100)",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "BitDefenderFalx": {
                              "category": "type-unsupported",
                              "engine_name": "BitDefenderFalx",
                              "engine_version": "2.0.936",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "AhnLab-V3": {
                              "category": "malicious",
                              "engine_name": "AhnLab-V3",
                              "engine_version": "3.23.3.10396",
                              "result": "Trojan/Win32.Agentb.R338979",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Acronis": {
                              "category": "malicious",
                              "engine_name": "Acronis",
                              "engine_version": "1.2.0.114",
                              "result": "suspicious",
                              "method": "blacklist",
                              "engine_update": "20230219"
                          },
                          "BitDefenderTheta": {
                              "category": "malicious",
                              "engine_name": "BitDefenderTheta",
                              "engine_version": "7.2.37796.0",
                              "result": "Gen:NN.ZexaF.36270.GBZ@a09Oi5ej",
                              "method": "blacklist",
                              "engine_update": "20230621"
                          },
                          "ALYac": {
                              "category": "malicious",
                              "engine_name": "ALYac",
                              "engine_version": "1.1.3.1",
                              "result": "Gen:Variant.Doina.58003",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "TACHYON": {
                              "category": "undetected",
                              "engine_name": "TACHYON",
                              "engine_version": "2023-06-26.02",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "DeepInstinct": {
                              "category": "malicious",
                              "engine_name": "DeepInstinct",
                              "engine_version": "3.1.0.15",
                              "result": "MALICIOUS",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "VBA32": {
                              "category": "malicious",
                              "engine_name": "VBA32",
                              "engine_version": "5.0.0",
                              "result": "SScope.Trojan.Agent.3915",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Malwarebytes": {
                              "category": "malicious",
                              "engine_name": "Malwarebytes",
                              "engine_version": "4.5.5.54",
                              "result": "PUP.Optional.ChinAd.DDS",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Panda": {
                              "category": "malicious",
                              "engine_name": "Panda",
                              "engine_version": "4.6.4.2",
                              "result": "Trj/Genetic.gen",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Zoner": {
                              "category": "undetected",
                              "engine_name": "Zoner",
                              "engine_version": "2.2.2.0",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "TrendMicro-HouseCall": {
                              "category": "malicious",
                              "engine_name": "TrendMicro-HouseCall",
                              "engine_version": "10.0.0.1040",
                              "result": "TROJ_GEN.R002C0PFP23",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Tencent": {
                              "category": "malicious",
                              "engine_name": "Tencent",
                              "engine_version": "1.0.0.1",
                              "result": "Trojan.Win32.Agentb.wj",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Yandex": {
                              "category": "malicious",
                              "engine_name": "Yandex",
                              "engine_version": "5.5.2.24",
                              "result": "Rootkit.Agent!FoGjttfAOnA",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Ikarus": {
                              "category": "malicious",
                              "engine_name": "Ikarus",
                              "engine_version": "6.1.14.0",
                              "result": "Trojan.Win32.Agentb",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "MaxSecure": {
                              "category": "undetected",
                              "engine_name": "MaxSecure",
                              "engine_version": "1.0.0.1",
                              "result": null,
                              "method": "blacklist",
                              "engine_update": "20230624"
                          },
                          "Fortinet": {
                              "category": "malicious",
                              "engine_name": "Fortinet",
                              "engine_version": "6.4.258.0",
                              "result": "W32/Agent.EB1!tr.dldr",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "AVG": {
                              "category": "malicious",
                              "engine_name": "AVG",
                              "engine_version": "22.11.7701.0",
                              "result": "Sf:ShellCode-C [Trj]",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          },
                          "Cybereason": {
                              "category": "malicious",
                              "engine_name": "Cybereason",
                              "engine_version": "1.2.449",
                              "result": "malicious.9a124a",
                              "method": "blacklist",
                              "engine_update": "20210330"
                          },
                          "Avast": {
                              "category": "malicious",
                              "engine_name": "Avast",
                              "engine_version": "22.11.7701.0",
                              "result": "Sf:ShellCode-C [Trj]",
                              "method": "blacklist",
                              "engine_update": "20230626"
                          }
                      },
                      "reputation": 1
                  },
                  "type": "file",
                  "id": "5751d5a9c55c4ba34651c183c72215263ec50a8c9162dce90cea5523d8dd42ec",
                  "links": {
                      "self": "https://www.virustotal.com/api/v3/files/5751d5a9c55c4ba34651c183c72215263ec50a8c9162dce90cea5523d8dd42ec"
                  }
              }
          ],
          "links": {
              "self": "https://www.virustotal.com/api/v3/search?query=5751d5a9c55c4ba34651c183c72215263ec50a8c9162dce90cea5523d8dd42ec"
          }
      }', headers: {})
      end

      it 'sends the hash to VirusTotal API and creates a report' do
        post :create, params: { input_hash: input_hash }, session:{'warden.user.user.key'=> [[1, 1],1]}

        expect(assigns(:report)).to be_a(Report)
        expect(assigns(:report).sha256).not_to be_nil
        expect(assigns(:report).score).not_to be_nil
      end
      it 'redirects to the created report' do
        post :create, params: { input_hash: input_hash }
        expect(response).to redirect_to(assigns(:report))
      end
    end
    context 'with an invalid input hash' do
      let(:input_hash) { 'invalid_hash' }
      before do
        stub_request(:get, "https://www.virustotal.com/api/v3/search?query=invalidHash").
         with(
           headers: {
          'Accept'=>'application/json',
          'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
          'Host'=>'www.virustotal.com',
          'User-Agent'=>'Ruby',
          'X-Apikey'=>'06066e396a57d2206a53847e115ace8c42e1c024af45131051e700af1919fccf'
           }).to_return(status: 200, body:'{
            "data": []
            }')
      end

      it 'redirects to the new action with a flash notice' do
        post :create, params: { input_hash: input_hash }
        expect(response).to redirect_to(new_hash_path)
        expect(flash[:notice]).to eq('hash incorrect or not present in the database')
      end
    end
  end

  # Other controller actions and tests...
end