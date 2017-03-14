#!/usr/bin/python

'''
#############################################################################

  THINKPWN SCANNER

  This program is used to scan UEFI drivers extracted from firmware image 
  for ThinkPwn vulnerability in vendor/model agnostic way.

  For more information about this vulenrability check the following links:

    https://github.com/Cr4sh/ThinkPwn
    http://blog.cr4.sh/2016/06/exploring-and-exploiting-lenovo.html


  AUTHORS: 

    @d_olex (aka Cr4sh) -- initial Vivisect based version of the program;
    @trufae (aka pankake) -- radare2 based version (this one); 


  To check the binary for ThinkPwn vulnerability we have to find a vulnerable 
  System Management Mode (SMM) callback that usually has the following look:    

                =------------------------------=
                | push rbx                     |
                | sub rsp, 0x20                |
                | mov rax, qword [rdx + 0x20]  |
                | mov rbx, rdx                 |
                | test rax, rax                |
                | je 0xa5c                     |
                =------------------------------=
                        f t
             .----------' '----------------.
             |                             |
             |                             |
     =-------------------------------=     |
     | mov rcx, qword [rax]          |     |
     | lea r8, [rdx + 0x18]          |     |
     | mov rdx, qword [rip + 0x5f4]  |     |
     | call qword [rax + 8]          |     |
     | and qword [rbx + 0x20], 0     |     |
     =-------------------------------=     |
         v                                 |
         '---------------.     .-----------'
                         |     |
                         |     |
                     =--------------------=
                     | xor eax, eax       |
                     | add rsp, 0x20      |
                     | pop rbx            |
                     | ret                |
                     =--------------------=


  And decompiled C code of this function:

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

  To match the vulnerable function shown above program uses a simple binary heuristics
  that checks number of basic blocks, instructions, global variable usage, etc. 
  See match_func() subroutine for more details.


  USAGE:

    1) Install radare2 and r2pipe for Python:

       https://radare.org/
       https://pypi.python.org/pypi/r2pipe

    2) Unpack UEFI firmware image from your computer using UEFIExtract, it's a part 
       of UEFITool (https://github.com/LongSoft/UEFITool):

       # UEFIExtract firmware_image.bin all

    3) Run scan_thinkpwn.py with path to the extracted firmware image contents as argument:

       # python scan_thinkpwn.py firmware_image.bin.dump

    4) At the end of the scan you will see the list of vulnerable SMM callbacks and UEFI
       drivers where they're located.


  Example of program output on vulnerable firmware from ThinkPad T450s:

    http://www.everfall.com/paste/id.php?cztv0fmo03gv


#############################################################################

'''

import os, sys, errno
from threading import Thread
from Queue import Queue

import r2pipe

# Do not load r2 plugins to speedup startup times
os.environ['R2_NOPLUGINS'] = '1'

# you might want to change these paramenetrs to tune the heuristics
BB_COUNT = 3
MAX_INSN = 10
MIN_INSN = 3
GUID_LEN = 0x10

# scan only EFI drivers that contains these GUIDs
GUID_LIST = \
[
    # SMM base protocol GUID
    '\x4D\x95\x90\x13\x95\xDA\x27\x42\x93\x28\x72\x82\xC2\x17\xDA\xA8',

    # SMM communication protocol GUID
    '\xE2\xD8\x8E\xC6\xC6\x9D\xBD\x4C\x9D\x94\xDB\x65\xAC\xC5\xC3\x32',

    # SMM communicate header GUID
    '\x6C\xE3\x28\xF3\xB6\x23\x95\x4A\x85\x4B\x32\xE1\x95\x34\xCD\x75'
]

WORKERS = 4

q, results = Queue(), []

def has_guid(file_path, guid_list, find_any = False):

    with open(file_path, 'rb') as fd:

        data, guid_found = fd.read(), []
        
        # lookup for one or all of the specified GUIDs inside file contents
        for guid in guid_list:

            if data.find(guid) != -1:

                if find_any: return True
                if not guid in guid_found: guid_found.append(guid)

        return len(guid_found) == len(guid_list)

def is_valid_file(file_path):

    with open(file_path, 'rb') as fd:

        # check for DOS header signature
        if fd.read(2) != 'MZ': return False

    # check if image contains needed GUIDs
    return has_guid(file_path, GUID_LIST, find_any = True)

def insn_uses_global(op):

    if op['type'] == 'mov':

        # get global variable information if MOV instruction is using it
        return ( op['esil'].find('rip,+,[8]') != -1, op['esil'].find('=[') != -1 )

    # not a MOV instruction    
    return (0, 0)

class BasicBlock(object):

    def __init__(self, r2, addr, size, insn_num):

        self.addr, self.size = addr, size
        self.insn_num = insn_num
        
        self.calls_total, self.calls_matched = 0, 0
        self.glob_reads, self.glob_writes = 0, 0
        
        # disassemble basic block
        r2ops = r2.cmdj('aoj %d @ 0x%x' % (insn_num, addr))

        # update instructions information
        for op in r2ops:
        
            # check for the CALL instruction
            self.check_call(op)

            # check for the MOV instruction with global variable as operand
            self.check_glob(op)

    def check_call(self, op):
        
        if op['type'] == 'call':

            # regular fucntion call
            self.calls_total += 1

        elif op['type'] == 'ucall' and op['opcode'].find('[') != -1:

            # call function by pointer
            self.calls_total += 1
            self.calls_matched += 1

    def check_glob(self, op):

        # check if instruction reads or writes some global variable
        r, w = insn_uses_global(op)
        if r: self.glob_reads += 1
        if w: self.glob_writes += 1

def match_func(r2, addr):

    bb_all = []

    # obtain list of basic blocks for given function
    bb_list = r2.cmdj('afbj %s' % addr)
    if len(bb_list) != BB_COUNT: return False
    
    for bb in bb_list:

        insn_num = bb['ninstr']
    
        # check basic block for proper amount of instruction
        if insn_num > MAX_INSN or insn_num < MIN_INSN:
            
            return False

        # analyze basic block
        bb = BasicBlock(r2, bb['addr'], bb['size'], insn_num)
        bb_all.append(bb)

    #
    # check calls and global variables usage for each basic block
    #
    if bb_all[0].calls_total != 0 or bb_all[0].calls_matched != 0: return False
    if bb_all[0].glob_reads  != 0 or bb_all[0].glob_writes   != 0: return False

    if bb_all[1].calls_total != 1 or bb_all[1].calls_matched != 1: return False
    if bb_all[1].glob_reads  != 1 or bb_all[1].glob_writes   != 0: return False
    
    if bb_all[2].calls_total != 0 or bb_all[2].calls_matched != 0: return False
    if bb_all[2].glob_reads  != 0 or bb_all[2].glob_writes   != 0: return False
    
    # vulnerable function was matched!
    return True

class Watcher:
    ''' This class solves two problems with multithreaded
    programs in Python, (1) a signal might be delivered
    to any thread (which is just a malfeature) and (2) if
    the thread that gets the signal is waiting, the signal
    is ignored (which is a bug). '''

    def __init__(self):
        ''' Creates a child thread, which returns.  The parent
        thread waits for a KeyboardInterrupt and then kills
        the child thread. '''

        self.child = os.fork()

        if self.child == 0: return
        else: self.watch()

    def watch(self):

        try:

            os.wait()

        except KeyboardInterrupt:

            print('\nEXIT')

            self.kill()

        sys.exit(errno.ECANCELED)

    def kill(self):

        try: os.kill(self.child, signal.SIGKILL)
        except OSError: pass

def scan_file(file_path):

    ret = []

    print('Scanning \"%s\"...' % file_path)

    # start radare instance
    r2 = r2pipe.open(file_path)

    # perform initial analysis
    r2.cmd('aa;aad')

    # enumerate available functions
    for addr in r2.cmdj('aflqj'):

        # check for vulnerable function
        if match_func(r2, addr):

            print('VULNERABLE FUNCTION: %s' % addr)

            ret.append(addr)

    # close radare instance
    r2.quit()

    return ret

def worker():

    global q, results

    while True:

        file_path = q.get()

        # scan single file
        procs = scan_file(file_path)

        if len(procs) > 0: 

            # save scan results
            results.append(( file_path, procs ))
        
        q.task_done()

def scan_dir(dir_path):

    for file_name in os.listdir(dir_path):

        file_path = os.path.join(dir_path, file_name)        

        if os.path.isfile(file_path) and is_valid_file(file_path):

            # queue scanning of the single file
            q.put(file_path)

        elif os.path.isdir(file_path):

            scan_dir(file_path)

def main():

    global q, results

    if len(sys.argv) < 2:

        print('USAGE: scan_thinkpwn.py <unpacked_firmware_dir>')
        return -1

    # ctrl+C handling stuff
    if sys.platform != 'win32': Watcher()

    # run worker threads
    for i in range(WORKERS):

         t = Thread(target = worker)
         t.daemon = True
         t.start()

    # scan files in target directory
    scan_dir(sys.argv[1])
    q.join()

    print('**************************************')
    print('SCAN RESULTS:')

    # print scan results
    for file_path, matched in results:

        print('\n' + file_path + '\n')

        for addr in matched:

            print(' * %s' % addr)

    print('')

    return 0

if __name__ == '__main__':

    exit(main())

#
# EoF
#
