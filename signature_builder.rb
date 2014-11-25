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
		sig = ""
		case i.id
		when X86::INS_CALL
			#Catch the case of call eax which translates to 0x50
                        if i.op_str.to_s =~ /[^0x]/
                                i.bytes.each {|x| sig << sprintf("%02X",x)}
                        else
                                sig << "E8"
                                (i.bytes.length - 1).times {|x| sig << "??"}
                        end
		when X86::INS_PUSH
			#Case when it's pushing an addr within the addr space 
                        if i.op_str.to_s.hex > @loadaddr && i.op_str.to_s.hex < @loadaddr+@max
                                sig << sprintf("%02X",i.bytes.first)
                                (i.bytes.length - 1).times {|x| sig << "??"}
                        else
                                i.bytes.each {|x| sig << sprintf("%02X",x)}
                        end
		when X86::INS_MOV
                        i.bytes.each {|x| sig << sprintf("%02X",x)}
		when X86::INS_RET
			break
		else
			i.bytes.each {|x| sig << sprintf("%02X",x)}
		end
		disasm << "#{i.bytes.map {|x| sprintf("%02X",x)}.join}\t\t#{i.mnemonic}\t#{i.op_str}\n"
		signature += sig	
	end
end

yara_format(disasm,signature)
