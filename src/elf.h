/*

Copyright (C) 2015, David "Davee" Morgan 

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions: 

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL 
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE. 


 */

#ifndef ELF_H_
#define ELF_H_

#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define ELF_MAGIC       (0x464C457F)
#define ELF_TYPE_PRX    (0xFFA0)

typedef struct {
	u32		e_magic;
	u8		e_class;
	u8		e_data; 
	u8		e_idver;
	u8		e_pad[9]; 
	u16		e_type;  
	u16		e_machine; 
	u32		e_version; 
	u32		e_entry; 
	u32		e_phoff; 
	u32		e_shoff; 
	u32		e_flags; 
	u16		e_ehsize;
	u16		e_phentsize;
	u16		e_phnum;
	u16		e_shentsize;
	u16		e_shnum;
	u16		e_shstrndx; 
} Elf32_Ehdr; 

/* ELF section header */
typedef struct { 
	u32		sh_name; 
	u32		sh_type; 
	u32		sh_flags;
	u32		sh_addr;
	u32		sh_offset;
	u32		sh_size; 
	u32		sh_link; 
	u32		sh_info; 
	u32		sh_addralign;
	u32		sh_entsize; 
}  Elf32_Shdr;

typedef struct {
	u32 p_type; 
	u32 p_offset;
	u32 p_vaddr; 
	u32 p_paddr; 
	u32 p_filesz;
	u32 p_memsz; 
	u32 p_flags; 
	u32 p_align; 
}  Elf32_Phdr; 

#endif // ELF_H_
