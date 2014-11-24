Yara Signature Tool
=============

Description
------------
This is a utility written in ruby using the Capstone Engine to build yara rules from functions.

For now, the script will wildcard out calls and pushes that are referencing locations within the binary addr space.


Requirements
------------
* Capstone Engine
* Crabstone
* PeDump
* optparse

Usage
------------
Run with the -h to get back the help (not much there so far)
```
Usage: signature_builder.rb -f ~/Desktop/wmiprivse.exe -o 0x401980 -e 0x401A08
    -f, --file FILE                  Filename
    -o, --offset NUMBER              Beginning Offset
    -e, --end NUMBER                 Ending Offset
    -h, --help                       Show this message
```
Ending offset is optional, if you like you can leave it blank and the code will follow until a RETN is hit.  The returned results printed in a form that you can copy and paste into an existing yara rule.
```
./signature_builder.rb -f evil.exe -o 0x401980
```
Which will return
```
    //6AFF		push	-1
    //6888834000		push	0x408388
    //64A100000000		mov	eax, dword ptr fs:[0]
    //50		push	eax
    //83EC0C		sub	esp, 0xc
    //56		push	esi
    //57		push	edi
    //A108054100		mov	eax, dword ptr [0x410508]
    //33C4		xor	eax, esp
    //50		push	eax
    //8D442418		lea	eax, dword ptr [esp + 0x18]
    //64A300000000		mov	dword ptr fs:[0], eax
    //6818934000		push	0x409318
    //E861FCFFFF		call	0x401610
    //B902030000		mov	ecx, 0x302
    //BE00B04000		mov	esi, 0x40b000
    //BF40054100		mov	edi, 0x410540
    //68FC924000		push	0x4092fc
    //F3A5		rep movsd	dword ptr es:[edi], dword ptr [esi]
    //E846FCFFFF		call	0x401610
    //83C408		add	esp, 8
    //8D4C240C		lea	ecx, dword ptr [esp + 0xc]
    //E8AA350000		call	0x404f80
    //C744242000000000		mov	dword ptr [esp + 0x20], 0
    //8D4C240C		lea	ecx, dword ptr [esp + 0xc]
    //E8994D0000		call	0x406780
    //C7442420FFFFFFFF		mov	dword ptr [esp + 0x20], 0xffffffff
    //8D4C240C		lea	ecx, dword ptr [esp + 0xc]
    //E828360000		call	0x405020
    //33C0		xor	eax, eax
    //8B4C2418		mov	ecx, dword ptr [esp + 0x18]
    //64890D00000000		mov	dword ptr fs:[0], ecx
    //59		pop	ecx
    //5F		pop	edi
    //5E		pop	esi
    //83C418		add	esp, 0x18
    //C21000		ret	0x10
    $a = {6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 0C 56 57 A1 08 05 41 00 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 02 03 00 00 BE 00 B0 40 00 BF 40 05 41 00 68 ?? ?? ?? ?? F3 A5 E8 ?? ?? ?? ?? 83 C4 08 8D 4C 24 0C E8 ?? ?? ?? ?? C7 44 24 20 00 00 00 00 8D 4C 24 0C E8 ?? ?? ?? ?? C7 44 24 20 FF FF FF FF 8D 4C 24 0C E8 ?? ?? ?? ?? 33 C0 8B 4C 24 18 64 89 0D 00 00 00 00 59 5F 5E 83 C4 18 C2 10 00 }

```
Status
------------
Alpha, still a lot of work to be done

To be implemented
------------
* wildcarding of mov's 
* wildcarding of lea's 
