
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import lief
from lief import ELF
import sys
import logging

import context
import IPython
import classes.symbol
import classes.config

class BinaryModifier:
    def __init__(self, config, path):
        classes.utils._desyl_init_class_(self, config)
        self.binary = lief.parse( path )

        #add symtab sections
        if not self.binary.has_section(".symtab"):
            self.logger.debug("Adding symtab")
            symtab_section             = ELF.Section()
            symtab_section.name        = ".symtab"
            symtab_section.type        = ELF.SECTION_TYPES.SYMTAB
            symtab_section.entry_size  = 0x18
            symtab_section.alignment   = 8
            symtab_section.information = 0 #1+number of symbols
            symtab_section.link        = len(self.binary.sections) + 1
            symtab_section.content     = [0] * (0x18 * 3000) #3000 symbols

            self.binary.add(symtab_section, loaded=False)
            #self.binary.sections[0] = symtab_section

        #add symtab sections
        if not self.binary.has_section(".strtab"):
            self.logger.debug("Adding symstr")
            symstr_section            = ELF.Section()
            symstr_section.name       = ".strtab"
            symstr_section.type       = ELF.SECTION_TYPES.STRTAB
            symstr_section.entry_size = 1
            symstr_section.alignment  = 1
            symstr_section.link        = self.find_section_index(".symtab")
            symstr_section.content    = [0] * 3000 * 10 #3000 symbols of 9 chars each

            self.binary.add(symstr_section, loaded=False)

        self.__add_initial_null_symbol()

    def __add_initial_null_symbol(self):
        """
            NB: NEED TO ADD AN INITIAL NULL SYMBOL
            However, readelf finds them but objdump and radare2 won't.
        """
        symbol         = ELF.Symbol()
        symbol.name    = ""
        symbol.type    = ELF.SYMBOL_TYPES.NOTYPE
        symbol.value   = 0
        symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
        symbol.size    = 0
        symbol.shndx   = 0
        symbol = self.binary.add_static_symbol(symbol)

    def read_symbols(self):
        #return self.binary.symbols #both static + dynamic iterator
        return list(self.binary.static_symbols)

    def add_symbols(self, symbols):
        symtab_section = self.binary.get_section(".symtab")
        symtab_section.information = 1 + len(symbols) #1+number of symbols
        symtab_section.content = [0]*(0x18*(1 + len(symbols)))
        for symbol in symbols:
            if(isinstance(symbol, classes.symbol.Symbol)):
                symbol = self.desyl_to_lief_symbol( symbol )
            self.logger.debug("Adding symbol: {}, {}, {}".format(symbol.name, symbol.value, symbol.size) )
            self.binary.add_static_symbol(symbol)

    def save(self, fpath):
        self.binary.write( fpath )

    def find_section_index(self, name):
        for i in range(len(self.binary.sections)):
            if self.binary.sections[i].name == name:
                return i
        return -1

    def simple_symbol(self, name, vaddr, size, section):
        #What section does the symbol reference

        shndx = self.find_section_index( section )
        assert(shndx >= 0)
        symbol         = ELF.Symbol()
        symbol.type    = ELF.SYMBOL_TYPES.FUNC
        symbol.binding = ELF.SYMBOL_BINDINGS.GLOBAL
        #IPython.embed()
        if not section:
            symbol.shndx   = ELF.SYMBOL_SECTION_INDEX.ABS
        else:
            symbol.shndx   = shndx

        #TODO REMOVE ABS, calculate relative offset from size of .text
        #symbol.shndx   = ELF.SYMBOL_SECTION_INDEX.ABS
        symbol.name    = name
        symbol.value   = vaddr
        symbol.size    = size
        return symbol

    @staticmethod
    def json_to_lief_symbol( j ):
        symb = lief.ELF.Symbol()
        for k, v in j.items():
            if k not in [ "binding", "demangled_name", "exported", "imported", "name", "shndx", "size", "type", "value" ]:
                continue

            symb[k] = v
        return symb
        
    def desyl_to_lief_symbol( self, symbol ):
        return self.simple_symbol( symbol.name, symbol.vaddr, symbol.size, ".text" )
