#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#  ida-sym2elf
#  28/11/2014
#
#  Daniel García <danigargu [at] gmail.com>
#  Jesús Olmos   <sha0 [at] badchecksum.net>
#
#  ELF parser - based on the lib of ROPgadget tool by Jonathan Salwan
#  http://shell-storm.org/project/ROPgadget/
# 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.
#

from idc       import *
from idaapi    import *
from idautils  import *

from ctypes    import *
from struct    import unpack

PLUG_NAME    = "syms2elf"
VERSION      = "v0.1"

STB_GLOBAL_FUNC = 0x12

class SHTypes:
    SHT_NULL      = 0
    SHT_PROGBITS  = 1
    SHT_SYMTAB    = 2
    SHT_STRTAB    = 3
    SHT_RELA      = 4
    SHT_HASH      = 5
    SHT_DYNAMIC   = 6
    SHT_NOTE      = 7
    SHT_NOBITS    = 8
    SHT_REL       = 9
    SHT_SHLIB     = 10
    SHT_DYNSYM    = 11
    SHT_NUM       = 12
    SHT_LOPROC    = 0x70000000
    SHT_HIPROC    = 0x7fffffff
    SHT_LOUSER    = 0x80000000
    SHT_HIUSER    = 0xffffffff

class ELFFlags:
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    EI_CLASS    = 0x04
    EI_DATA     = 0x05
    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02
    EM_386      = 0x03
    EM_X86_64   = 0x3e
    EM_ARM      = 0x28
    EM_MIPS     = 0x08
    EM_SPARCv8p = 0x12
    EM_PowerPC  = 0x14
    EM_ARM64    = 0xb7

class SymFlags:
    STB_LOCAL   = 0
    STB_GLOBAL  = 1
    STB_WEAK    = 2
    STT_NOTYPE  = 0
    STT_OBJECT  = 1
    STT_FUNC    = 2
    STT_SECTION = 3
    STT_FILE    = 4
    STT_COMMON  = 5
    STT_TLS     = 6

class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Sym_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]

class Elf64_Sym_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]

class Elf32_Sym_MSB(BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]

class Elf64_Sym_MSB(BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]


""" This class parses the ELF """
class ELF:
    def __init__(self, binary):
        self.binary    = bytearray(binary)
        self.ElfHeader = None
        self.shdr_l    = []
        self.phdr_l    = []
        self.syms_l    = []
        self.e_ident   = str(self.binary[:15]) 
        self.ei_data   = unpack("<B", self.e_ident[ELFFlags.EI_DATA])[0] # LSB/MSB
        
        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()

    def is_stripped(self):
        if not self.has_symtab():
            return True
        if not self.has_strtab():
            return True
        return False

    def strip_symbols(self):
        sections2delete = 0

        if self.has_symtab():
            sections2delete += 1
            log("Deleting section .symtab")
            
        if self.has_strtab():
            sections2delete += 1
            log("Deleting section .strtab")

        for i in range(0,sections2delete):
            self.shdr_l.pop()

        self.ElfHeader.e_shnum -= sections2delete
        
        e_shnum = self.ElfHeader.e_shnum
        e_shoff = self.ElfHeader.e_shoff
        sz_striped = (e_shoff + (e_shnum * self.sizeof_sh()))
        bytes_deleted = len(self.binary) - sz_striped

        # strip
        self.binary = self.binary[0:sz_striped]

    def has_symtab(self):
        for idx, sh in enumerate(self.shdr_l):
            if sh.sh_type == SHTypes.SHT_SYMTAB:
                return True
        return False

    def has_strtab(self):
        end_shdr = self.ElfHeader.e_shoff + (self.sizeof_sh() * self.ElfHeader.e_shnum)
        
        for idx, sh in enumerate(self.shdr_l):
            if sh.sh_type == SHTypes.SHT_STRTAB:
                if sh.sh_offset >= end_shdr:
                    return True
        return False

    def getArchMode(self):
        if self.ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32: 
            return 32
        elif self.ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64: 
            return 64
        else:
            log("[Error] ELF.getArchMode() - Bad Arch size")
            return None

    """ Parse ELF header """
    def __setHeaderElf(self):
        e_ident = str(self.binary[:15])

        ei_class = unpack("<B", e_ident[ELFFlags.EI_CLASS])[0]
        ei_data  = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            log("[Error] ELF.__setHeaderElf() - Bad Arch size")
            return None

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            log("[Error] ELF.__setHeaderElf() - Bad architecture endian")
            return None

        if ei_class == ELFFlags.ELFCLASS32: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.binary)
        elif ei_class == ELFFlags.ELFCLASS64: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.binary)

    """ Write the section header to self.binary """
    def write_shdr(self):
        off = self.ElfHeader.e_shoff
        for sh in self.shdr_l:
            self.write(off, sh)
            off += off + sizeof(sh) 

    """ Parse Section header """
    def __setShdr(self):
        shdr_num = self.ElfHeader.e_shnum
        base = self.binary[self.ElfHeader.e_shoff:]
        shdr_l = []

        e_ident = str(self.binary[:15])
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        for i in range(shdr_num):
            if self.getArchMode() == 32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == 64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

            self.shdr_l.append(shdr)
            base = base[self.ElfHeader.e_shentsize:]

        string_table = str(self.binary[(self.shdr_l[self.ElfHeader.e_shstrndx].sh_offset):])
        for i in range(shdr_num):
            self.shdr_l[i].str_name = string_table[self.shdr_l[i].sh_name:].split('\0')[0]

    """ Parse Program header """
    def __setPhdr(self):
        pdhr_num = self.ElfHeader.e_phnum
        base = self.binary[self.ElfHeader.e_phoff:]
        phdr_l = []

        e_ident = str(self.binary[:15])
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        for i in range(pdhr_num):
            if self.getArchMode() == 32:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == 64:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)

            self.phdr_l.append(phdr)
            base = base[self.ElfHeader.e_phentsize:]

    def get_section_id(self, sh_name):
        for idx, sh in enumerate(self.shdr_l):
            if sh.str_name == sh_name:
                return idx
        return None

    def disable_symtabs(self):
        for idx, sh in enumerate(self.shdr_l):
            if sh.sh_type == SHTypes.SHT_SYMTAB:
                sh.sh_type = SHTypes.SHT_NULL

    def disable_strtabs(self):        
        """
        I think is not necesary disable strtab becouse
        elf support multiple strtabs and the refereced one 
        will be the accessed by the debugger
        """
        for idx, sh in enumerate(self.shdr_l):
            if sh.sh_type == SHTypes.SHT_STRTAB:
                sh.sh_type = SHTypes.SHT_NULL

    def get_sh_symtab(self):
        for idx, sh in enumerate(self.shdr_l):
            if sh.sh_type == SHTypes.SHT_SYMTAB:
                return idx, sh
        return None,None

    def get_sym_at_offset(self, off):
        if self.getArchMode() == 32:
            if   ei_data == ELFFlags.ELFDATA2LSB: sym = Elf32_Sym_LSB.from_buffer_copy(self.binary[off:])
            elif ei_data == ELFFlags.ELFDATA2MSB: sym = Elf32_Sym_MSB.from_buffer_copy(self.binary[off:])
        elif self.getArchMode() == 64:
            if   ei_data == ELFFlags.ELFDATA2LSB: sym = Elf64_Sym_LSB.from_buffer_copy(self.binary[off:])
            elif ei_data == ELFFlags.ELFDATA2MSB: sym = Elf64_Sym_MSB.from_buffer_copy(self.binary[off:])
        return sym

    def ida_func_filter(self, func_ea):
        if SegName(func_ea) not in ("extern", ".plt"):
            return True
        return False 

    def get_ida_symbols(self):
        symbols = []

        for f in filter(self.ida_func_filter, Functions()):
            func     = get_func(f)
            seg_name = SegName(f)
            sh_idx   = self.get_section_id(seg_name)
            
            if not sh_idx:
                continue

            fn_name = GetFunctionName(f)
            symbols.append(Symbol(fn_name, STB_GLOBAL_FUNC, 
                int(func.startEA), int(func.size()), seg_name, sh_idx))

        return symbols

    def get_entrypoint(self):
        return self.e_entry

    def sizeof_sh(self):
        size = None
        if self.getArchMode() == 32:
            size = sizeof(Elf32_Shdr_LSB())
        elif self.getArchMode() == 64:
            size = sizeof(Elf64_Shdr_LSB())
        return size

    def sizeof_sym(self):
        size = None
        if self.getArchMode() == 32:
            size = sizeof(Elf32_Sym_LSB)
        elif self.getArchMode() == 64:
            size = sizeof(Elf64_Sym_LSB)
        return size

    def edit_section_header(self, section):
        sh = None

        sh.sh_name      = section["name"]
        sh.sh_type      = section["type"]
        sh.sh_flags     = section["flags"]
        sh.sh_addr      = section["addr"]
        sh.sh_offset    = section["offset"]
        sh.sh_size      = section["size"]
        sh.sh_link      = section["link"]
        sh.sh_info      = section["info"]
        sh.sh_addralign = section["addralign"]
        sh.sh_entsize   = section["entsize"]

        self.binary.extend(sh)

    def append_section_header(self, section):
        sh = None

        if self.getArchMode() == 32:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sh = Elf32_Shdr_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sh = Elf32_Shdr_MSB()
        elif self.getArchMode() == 64:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sh = Elf64_Shdr_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sh = Elf64_Shdr_MSB()

        sh.sh_name      = section["name"]
        sh.sh_type      = section["type"]
        sh.sh_flags     = section["flags"]
        sh.sh_addr      = section["addr"]
        sh.sh_offset    = section["offset"]
        sh.sh_size      = section["size"]
        sh.sh_link      = section["link"]
        sh.sh_info      = section["info"]
        sh.sh_addralign = section["addralign"]
        sh.sh_entsize   = section["entsize"]

        self.binary.extend(sh)

    def append_symbol(self, symbol):
        if self.getArchMode() == 32:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sym = Elf32_Sym_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sym = Elf32_Sym_MSB()
        elif self.getArchMode() == 64:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sym = Elf64_Sym_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sym = Elf64_Sym_MSB()

        sym.st_name   = symbol["name"]
        sym.st_value  = symbol["value"]
        sym.st_size   = symbol["size"]
        sym.st_info   = symbol["info"]
        sym.st_other  = symbol["other"]
        sym.st_shndx  = symbol["shndx"]

        self.binary.extend(sym)

    def get_binary(self):
        return self.binary

    def write(self, offset, data):
        self.binary[offset:offset+sizeof(data)] = data

    def expand_at_offset(self, offset, data):
        self.binary[:] = self.binary[:offset] + data + self.binary[offset:]

    def save(self, output):
        with open(output, 'wb') as f:
            f.write(self.binary)

class Symbol:
    def __init__(self, name, info, value, size, shname, shndx=0):
        self.name   = name
        self.info   = info
        self.value  = value
        self.size   = size
        self.shname = shname
        self.shndx  = shndx

    def __str__(self):
        return "%s;%s;%s;%s;%s" % (self.name, self.value, self.size, 
            self.info, self.shname)

def write_symbols(input_file, output_file):

    try:
        log("Exporting symbols to ELF")

        with open(input_file, 'rb') as f:
            bin = ELF(f.read())

        symbols = bin.get_ida_symbols()
        if len(symbols) < 0:
            warning("No symbols to export")
            return

        bin.strip_symbols()

        # raw strtab
        strtab_raw = "\x00" + "\x00".join([sym.name for sym in symbols]) + "\x00"

        symtab = {
            "name"      : 0, # SHN_UNDEF
            "type"      : SHTypes.SHT_SYMTAB,
            "flags"     : 0,
            "addr"      : 0,
            "offset"    : len(bin.binary) + (bin.sizeof_sh() * 2),
            "size"      : (len(symbols) + 1) * bin.sizeof_sym(),
            "link"      : len(bin.shdr_l) + 1,
            "info"      : 1,
            "addralign" : 4,
            "entsize"   : bin.sizeof_sym()
        }

        off_strtab = (len(bin.binary) + (bin.sizeof_sh() * 2) + (bin.sizeof_sym() * (len(symbols) + 1)))

        strtab = {
            "name"      : 0, # SHN_UNDEF
            "type"      : SHTypes.SHT_STRTAB,
            "flags"     : 0,
            "addr"      : 0,
            "offset"    : off_strtab,
            "size"      : len(strtab_raw),
            "link"      : 0,
            "info"      : 0,
            "addralign" : 1,
            "entsize"   : 0
        }

        bin.ElfHeader.e_shnum += 2
        bin.write(0,bin.ElfHeader)
        bin.append_section_header(symtab)
        bin.append_section_header(strtab)

        # Local symbol - separator
        sym = {
            "name"  : 0,
            "value" : 0,
            "size"  : 0,
            "info"  : SymFlags.STB_LOCAL,
            "other" : 0,
            "shndx" : 0 
        }
        bin.append_symbol(sym)

        # add symbols  
        for s in symbols:
            sym = {
                "name"  : strtab_raw.index(s.name),
                "value" : s.value,
                "size"  : s.size,
                "info"  : s.info,
                "other" : 0,
                "shndx" : s.shndx 
            }

            log("%s (0x%08x)" % (s.name, s.value))
            bin.append_symbol(sym)

        # add symbol strings
        bin.binary.extend(strtab_raw)

        log("ELF saved to: %s\n" % output_file)
        bin.save(output_file)

    except:
        log(traceback.format_exc())

def log(msg):
  Message("[%s] %s\n" % (PLUG_NAME, msg))

class Syms2Elf(Form):
    def __init__(self):
        Form.__init__(self, r"""syms2elf
{formChangeCb}
<#Output file#Output ~f~ile:{txtFile}>
""", {
        'formChangeCb' : Form.FormChangeCb(self.OnFormChange),
        'txtFile' : Form.FileInput(save=True, swidth=50)
    })

        self.input_elf = GetInputFilePath()

    def OnFormChange(self, fid):
        if fid == self.txtFile.id:
            o_file = self.GetControlValue(self.txtFile)

            if os.path.exists(o_file):
                s = "Output file already exists\n" \
                    "The output file already exists. " \
                    "Do you want to overwrite it?"

                if bool(AskUsingForm(s, "1")):
                    os.remove(o_file)
                else:
                    self.SetControlValue(self.txtFile, '')
        return 1

    def Show(self):
        if not self.Compiled():
            self.Compile()

        if "ELF" in get_file_type_name():
            ok = self.Execute()
        else:
            warning("The file is not a ELF")
            ok = 0
        return ok

class Syms2Elf_t(plugin_t):
    flags = PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = PLUG_NAME
    wanted_hotkey = ""

    def init(self):
        return PLUGIN_OK

    def run(self, arg=0):
        f = Syms2Elf()

        if f.Show():
            output_file = f.txtFile.value
            write_symbols(f.input_elf, output_file)
            f.Free()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return Syms2Elf_t()


