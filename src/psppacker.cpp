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

#include <iostream>
#include <fstream>
#include <iterator>

#include <cstring>

#include "packexec.h"

void usage(void)
{
    std::cout << "psp-packer by Davee" << std::endl;
    std::cout << "usage: psp-packer [-s <tag> <oetag>] file" << std::endl;
}

int main(int argc, char *argv[])
{
    const char *filename = argv[1];
    TagHandler pspTagHandler = [](ExecutableType type) -> unsigned int
    {
        switch (type)
        {
            default:
            case EXECUTABLE_TYPE_USER_PRX:
                return 0x457B06F0;
            case EXECUTABLE_TYPE_KERNEL_PRX:
                return 0xDADADAF0;
            case EXECUTABLE_TYPE_PBP:
                return 0xADF305F0;
        }
    };
 
    TagHandler oeTagHandler = [](ExecutableType type) -> unsigned int
    {
        switch (type)
        {
            default:
            case EXECUTABLE_TYPE_USER_PRX:
                return 0x8555ABF2;
            case EXECUTABLE_TYPE_KERNEL_PRX:
                return 0x55668D96;
            case EXECUTABLE_TYPE_PBP:
                return 0x7316308C;
        }
    };
    
    if (argc != 2 && argc != 5)
    {
        usage();
        return 0;
    }
    
    // check if no options mode
    if (argc == 2)
    {
        filename = argv[1];
    }
    // check if specified tags
    else if (argc == 5 && std::strcmp(argv[1], "-s") == 0)
    {
        filename = argv[4];
        
        auto psptag = strtoul(argv[2], NULL, 0);
        auto oetag = strtoul(argv[3], NULL, 0);
        
        pspTagHandler = [=](ExecutableType type) -> unsigned int { return psptag; };
        oeTagHandler = [=](ExecutableType type) -> unsigned int { return oetag; };
    }
    
    // else is error
    else
    {
        usage();
        return 0;
    }
    
    std::ifstream file(filename, std::ios::binary);
    
    // check if file error
    if (!file.is_open())
    {
        std::cout << "could not open file: \"" << filename << "\"." << std::endl;
        return 0;
    }
    
    // read file into buffer
    ExecBuffer executable((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                 
    file.close();
    
    int res = pack_executable(executable, pspTagHandler, oeTagHandler);
    
    if (res != NO_ERROR)
    {
        printf("Error 0x%08X packing executable %s.\n", res, filename);
        return 0;
    }
    
    std::ofstream ofile(filename, std::ios::binary);
    ofile.write(executable.data(), executable.size());
    return 0;
}
