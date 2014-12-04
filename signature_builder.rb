#!/usr/bin/env ruby

require 'crabstone'
require 'pedump'
require 'optparse'

include Crabstone

###############
#You point this script at a function start addr and it'll build a signature starting at start addr and continuing until retn
###############

def fetch_real_addr(offset)
	begin
		return @pe.dump.va2file(offset - @loadaddr)
	rescue Exception => err
		return nil
	end
end

def yara_format(instructions, rule)
	instructions.each {|line| puts "\s\s\s\s//#{line}"}
	print "\s\s\s\s$a = {"
	rule.scan(/../).each {|x| print x+"\s"}
	print "}"
	puts
end

options = Hash.new
OptionParser.new do |opts|
	opts.banner = "Usage: signature_builder.rb -f ~/Desktop/wmiprivse.exe -o 0x401980 -e 0x401A08"
	opts.on("-f","--file FILE", "Filename") do |file|
		options[:file] = file
	end
        opts.on("-o","--offset NUMBER", "Beginning Offset") do |num|
                options[:offset] = num.hex.to_i
        end
        opts.on("-e","--end NUMBER", "Ending Offset") do |num|
                options[:end] = num.hex.to_i
        end
	opts.on("-h","--help", "Show this message") do 
                puts opts
		exit
        end
end.parse!

if options[:file] and options[:offset]
	f = File.new(options[:file],'rb')
	file = f.read
	f.close
	@pe = PEdump.new(options[:file]).dump
	@loadaddr = @pe.dump.pe.ioh.ImageBase
	@max = @pe.pe.sections.map {|x| x['VirtualSize']+x['VirtualAddress']}.max
	start = fetch_real_addr(options[:offset])
	if options[:end]
		if fetch_real_addr(options[:end]) #check to see if an error is thrown
			ending = fetch_real_addr(options[:end])
		else
			ending = @max
		end
	else
		ending = @max
	end
	item = file[start..ending]
	signature = ""
	disasm = []
	cs = Disassembler.new(ARCH_X86, MODE_32)
	cs.disasm(item,options[:offset]).each do |i|
		byte = i.bytes.first
		sig = ""
		case i.id
		#x86 Call
		when X86::INS_CALL
                        if byte.eql?(0xff)
				#Call near, absolute indirect
				#FF15D0904000		call	dword ptr [0x4090d0]
				#FFD0                   call    eax
				sig << "FF"
                        	(i.bytes.length - 1).times {|x| sig << "??"}
			elsif byte.eql?(0x9a)
				#Call far, absolute, address given in operand
                                sig << "9A"
                                (i.bytes.length - 1).times {|x| sig << "??"}
			else
				#Default case, E8
				#Call near, relative, displacement relative to next instruction
				#E864310000                call    sub_404950
                                sig << "E8"
                                (i.bytes.length - 1).times {|x| sig << "??"}
                        end

		#x86 push
		when X86::INS_PUSH
			if byte.eql?(0xff) 
				#Push with dword to addr
				#FF35B0AF4100             push    dword_41AFB0
				sig << sprintf("%02X",i.bytes.first)
                                (i.bytes.length - 1).times {|x| sig << "??"}
			elsif byte.eql?(0x68)
				#push imm
				#6814954000               push    offset szVerb  
				#reverse the rest and see if they exist between imagebase and imagebase + max
				data = i.bytes[1..i.bytes.length].reverse.map {|x| sprintf("%02X",x) }.join.hex
				if data > @loadaddr && data < @loadaddr+@max
                                	sig << sprintf("%02X",i.bytes.first)
                                	(i.bytes.length - 1).times {|x| sig << "??"}
				else
					i.bytes.each {|x| sig << sprintf("%02X",x)}
				end
                        else
				#Default case
				#6a Push Constant
				#6AFF                     push    0FFFFFFFFh
				#0x50 - 0x57
				#push esi/edi/eax/ecx ......
                                i.bytes.each {|x| sig << sprintf("%02X",x)}
                        end
		when X86::INS_MOV
			#wildcard if it's pushing an address within our imagebase and imagebase + max
			#the easiest way atm to check for this is to check the length and look for a little endian
			#set of bytes that look like an addr
			if i.bytes.length > 5
				#potential canidate for a mov
				#668B1504424100          mov     dx, ds:word_414204
				#take the last 4 bytes for the and that should be our addr
				#the following example is should become
				#8B15FC414100		mov	edx, dword ptr [0x4141fc]
    				#8B0D00424100		mov	ecx, dword ptr [0x414200]
    				#8910		mov	dword ptr [eax], edx
    				#668B1504424100		mov	dx, word ptr [0x414204]
    				#53		push	ebx
				#should become
    				#8B 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 10 66 8B 15 ?? ?? ?? ?? 53 

				data = i.bytes[i.bytes.length-4..i.bytes.length].reverse.map {|x| sprintf("%02X",x) }.join.hex
				if data > @loadaddr && data < @loadaddr+@max
					i.bytes[0..(i.bytes.length-5)].each {|x| sig << sprintf("%02X",x)}
					4.times {|x| sig << "??"}
				else
					i.bytes.each {|x| sig << sprintf("%02X",x)}
				end
			else
                        	i.bytes.each {|x| sig << sprintf("%02X",x)}
			end
		when X86::INS_RET
			break
		when 255..274  
			#all of our jump cases, we'll wild card these including the actual jump
			i.bytes.length.times {|x| sig << "??"}
		else
			i.bytes.each {|x| sig << sprintf("%02X",x)}
		end
		disasm << "#{i.bytes.map {|x| sprintf("%02X",x)}.join}\t\t#{i.mnemonic}\t#{i.op_str}\n"
		signature += sig	
	end
end

yara_format(disasm,signature)
