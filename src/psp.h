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

#ifndef PSP_H_
#define PSP_H_

#include <stdint.h>

#define PSP_HEADER_MAGIC    (0x5053507E)
#define PBP_HEADER_MAGIC    (0x50425000)

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef struct
{
	u32		signature; 
	u16		attribute; 
	u16		comp_attribute; 
	u8		module_ver_lo;	
	u8		module_ver_hi;	
	char	modname[28];
	u8		version; 
	u8		nsegments; 
	int		elf_size; 
	int		psp_size; 
	u32		entry;	
	u32		modinfo_offset; 
	int		bss_size; 
	u16		seg_align[4]; 
	u32		seg_address[4];
	int		seg_size[4]; 
	u32		reserved[5]; 
	u32		devkitversion; 
	u8		decrypt_mode; 
	u8		padding; 
	u16		overlap_size; 
	u8		key_data0[0x30]; 
	int		comp_size; 
	int		_80;
	int		reserved2[2];	
	u8		key_data1[0x10];
	u32		tag; 
	u8		scheck[0x58];
	u32		key_data2;
	u32		oe_tag; 
	u8		key_data3[0x1C]; 
}  PSP_Header;

typedef struct _scemoduleinfo {
	unsigned short		modattribute;
	unsigned char		modversion[2];
	char			modname[27];
	char			terminal;
	void *			gp_value;
	void *			ent_top;
	void *			ent_end;
	void *			stub_top;
	void *			stub_end;
} _sceModuleInfo;

typedef _sceModuleInfo SceModuleInfo;

typedef struct
{
    u32 magic;
    u32 version;
    u32 sfo_offset;
    u32 icon0_offset;
    u32 icon1_offset;
    u32 pic0_offset;
    u32 pic1_offset;
    u32 snd0_offset;
    u32 prx_offset;
    u32 psar_offset;
} PbpHeader;

#endif // PSP_H_
