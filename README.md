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
./signature_builder.rb -f ~/Desktop/wmiprivse.exe -o 0x4017d3 -e 0x4017f9
```
Which will return
```
    //6804010000		push	0x104
    //8D8C24A4000000		lea	ecx, dword ptr [esp + 0xa4]
    //51		push	ecx
    //8D54246C		lea	edx, dword ptr [esp + 0x6c]
    //6A08		push	8
    //52		push	edx
    //E864310000		call	0x404950
    //83C408		add	esp, 8
    //50		push	eax
    //FF15D0904000		call	dword ptr [0x4090d0]
    //85C0		test	eax, eax
    //7516		jne	0x401810
    $a = {68 04 01 00 00 8D 8C 24 A4 00 00 00 51 8D 54 24 6C 6A 08 52 E8 ?? ?? ?? ?? 83 C4 08 50 FF ?? ?? ?? ?? ?? 85 C0 75 16 }


```
Status
------------
Alpha, still a lot of work to be done

To be implemented
------------
* wildcarding of mov's 
* wildcarding of lea's 
* wildcarding of jmp's to absolute locations
