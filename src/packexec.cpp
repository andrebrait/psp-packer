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

#include "packexec.h"

#include "elf.h"
#include "psp.h"
#include "gzip.h"

#include <random>
#include <cstring>

Elf32_Phdr *findModuleInfoHeader(Elf32_Ehdr *elf)
{
	auto phdr = (Elf32_Phdr *)((char *)elf + elf->e_phoff);
	
	// loop through the sections
	for (int phnum = elf->e_phnum; phnum > 0; --phnum, ++phdr)
	{
		// p_type is 1 for module info
		if (phdr->p_type == 1)
		{
            if (phdr->p_vaddr != phdr->p_paddr)
            {
                // found module info
                return phdr;
            }
            
            break;
		}
	}
    
    return nullptr;
}

bool readSegmentAndBssInfo(PSP_Header *psp_header, Elf32_Ehdr *elf)
{
    auto bssFound = false;
	auto phdr = (Elf32_Phdr *)((char *)elf + elf->e_phoff);
	
	for (int i = 0; i < psp_header->nsegments; ++i)
	{
		/* copy the segment info */
		psp_header->seg_align[i] = phdr[i].p_align;
		psp_header->seg_address[i] = phdr[i].p_vaddr;
		psp_header->seg_size[i] = phdr[i].p_memsz;
	}
	
	auto shdr = (Elf32_Shdr *)((char *)elf + elf->e_shoff);
	auto strtab = (char *)((char *)elf + shdr[elf->e_shstrndx].sh_offset);
	
    // look for bss section
	for (int i = 0; i < elf->e_shnum; ++i)
	{
		/* check if this section is called ".bss" */
		if (std::strcmp(strtab + shdr[i].sh_name, ".bss") == 0)
		{
			/* copy over the .bss size */
			psp_header->bss_size = shdr[i].sh_size;
            bssFound = true;
			break;
		}
	}
	
	// return false if we didn't find bss 
    return bssFound;
}

void setDecryptMode(PSP_Header *psp_header, bool isPbp)
{
    // is kernel mode
    if (psp_header->attribute & 0x1000)
    {
        // check if boot mode flag
        if (psp_header->attribute & 0x2000)
        {
            psp_header->devkitversion = 0x06060110;
        }
        else
        {
            psp_header->devkitversion = 0x05070110;
        }
        
        psp_header->decrypt_mode = 2;
    }
    else
    {
        if (isPbp)
        {
 			// check for VSH API (updater)
			if (psp_header->attribute & 0x800)
			{
				// set the decryption mode to updater
				psp_header->decrypt_mode = 0xC;
			}
			
			// check for APP API (comics, etc)
			else if (psp_header->attribute & 0x600)
			{
				// set the decryption mode to app
				psp_header->decrypt_mode = 0xE;
			}
			
			// check for USB WLAN API (skype, etc)
			else if (psp_header->attribute & 0x400)
			{
				// set the decryption mode to USB WLAN 
				psp_header->decrypt_mode = 0xA;
			}
			
			// else set to MS API 
			else
			{
				// TODO: could check the SFO for POPS...
				psp_header->attribute |= 0x200;
				psp_header->decrypt_mode = 0xD;
			}       
        }
        else
        {
            // standalone user prx
            // check for VSH API
			if (psp_header->attribute & 0x800)
			{
				// set vsh decrypt mode
				psp_header->decrypt_mode = 0x3;
			}
			
			else
			{
				// set to standard 
				psp_header->devkitversion = 0x05070210;
				psp_header->decrypt_mode = 4;
			}
        }
    }
}

int pack_executable(ExecBuffer& executable, TagHandler psptagHandler, TagHandler oetagHandler)
{
    auto fileMagic = ((unsigned int *)executable.data())[0];
    auto execSize = (int)executable.size();
    auto execType = EXECUTABLE_TYPE_USER_PRX;
    auto execOffset = 0;
    
    // check if ~PSP packed
    if (fileMagic == PSP_HEADER_MAGIC)
    {
        return ERROR_ALREADY_PACKED;
    }
    
    if (fileMagic == PBP_HEADER_MAGIC)
    {
        auto pbp = (PbpHeader *)(executable.data());
        execSize = pbp->psar_offset - pbp->prx_offset;
        execType = EXECUTABLE_TYPE_PBP;
        execOffset = pbp->prx_offset;
    }
    
    auto elfHeader = (Elf32_Ehdr *)(executable.data()+execOffset);
    
    if (elfHeader->e_magic != ELF_MAGIC || elfHeader->e_type != ELF_TYPE_PRX)
    {
        return ERROR_NOT_PRX;
    }
    
    auto modinfoPhdr = findModuleInfoHeader(elfHeader);
    
    if (modinfoPhdr == nullptr)
    {
        return ERROR_NO_MODULEINFO;
    }
    
    auto isKernelModule = ((modinfoPhdr->p_paddr & 0x80000000) != 0);
    auto modinfo = (SceModuleInfo *)(executable.data()+execOffset+(modinfoPhdr->p_paddr & 0x7FFFFFFF));
    
    // check for mixed privileges with kernel module
    if ((isKernelModule && (modinfo->modattribute & 0x1000) == 0) 
    || (!isKernelModule && (modinfo->modattribute & 0x1000) != 0))
    {
        return ERROR_MIXED_PRIVILEGES;
    }
    
    // check for kernel PBP
    if (isKernelModule && execType == EXECUTABLE_TYPE_PBP)
    {
        return ERROR_KERNEL_PBP;
    }
    
    // if not kernel PBP but is kernel flag set, then we must change exec type
    else if (isKernelModule)
    {
        execType = EXECUTABLE_TYPE_KERNEL_PRX;
    }
    
    
    // prepare for gzip compression
    auto predictSize = gzipGetMaxCompressedSize(execSize);
    ExecBuffer compressedExec(predictSize + sizeof(PSP_Header));
    
    auto psp_header = (PSP_Header *)(compressedExec.data());
    
    psp_header->signature = PSP_HEADER_MAGIC;
    psp_header->attribute = modinfo->modattribute;
    psp_header->modinfo_offset = modinfoPhdr->p_paddr;
    psp_header->version = 1;
    
    // set comp attribute to use gzip
    psp_header->comp_attribute = 1;
	psp_header->module_ver_lo = modinfo->modversion[0];
	psp_header->module_ver_hi = modinfo->modversion[1];
    strcpy(psp_header->modname, modinfo->modname);
    psp_header->_80 = 0x80;
    
    // set exec size and entry location
    psp_header->elf_size = execSize;
    psp_header->entry = elfHeader->e_entry;
    
    // set number of segments
	psp_header->nsegments = (elfHeader->e_phnum > 2) ? (2) : (elfHeader->e_phnum);
    
    // check for 0 segments
    if (psp_header->nsegments == 0)
    {
        return ERROR_NO_SEGMENTS;
    }
    
    // read segment info and bss
    if (!readSegmentAndBssInfo(psp_header, elfHeader))
    {
        return ERROR_NO_BSS_SECTION;
    }
    
    setDecryptMode(psp_header, execType == EXECUTABLE_TYPE_PBP);
    
    // update modinfo for changes
    modinfo->modattribute = psp_header->attribute;
    
    // set the tags based off executable type
    psp_header->tag = psptagHandler(execType);
    psp_header->oe_tag = oetagHandler(execType);
    
    // compress executable
    auto compExecSize = gzipCompress(compressedExec.data()+sizeof(PSP_Header), predictSize, executable.data()+execOffset, execSize);
    
    if (compExecSize < 0)
    {
        return ERROR_GZIP_COMPRESSION;
    }
    
    // resize the container
    compressedExec.resize(compExecSize+sizeof(PSP_Header));
    
    // update psp header
    psp_header->comp_size = compExecSize;
    psp_header->psp_size = compExecSize + sizeof(PSP_Header);
    
    // fill key data with random data
    std::random_device rd;
    
    for (int i = 0; i < 0x30; ++i)
    {
        psp_header->key_data0[i] = rd();
    }
    
    for (int i = 0; i < 0x10; ++i)
    {
        psp_header->key_data1[i] = rd();
    }
    
    for (int i = 0; i < 0x1C; ++i)
    {
        psp_header->key_data3[i] = rd();
    }
    
    // if PBP we need to insert the PBP header/icons etc
    if (execType == EXECUTABLE_TYPE_PBP)
    {
        compressedExec.insert(compressedExec.end(), executable.begin()+execOffset+execSize, executable.end());
        compressedExec.insert(compressedExec.begin(), executable.begin(), executable.begin()+execOffset);
        
        // set the psar offset
        auto pbp = (PbpHeader *)(compressedExec.data());
        pbp->psar_offset = execOffset+compExecSize;
    }
    
    executable.swap(compressedExec);
    return NO_ERROR;
}
