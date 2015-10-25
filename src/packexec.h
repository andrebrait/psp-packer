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

#ifndef PACKEXEC_H_
#define PACKEXEC_H_

#include <functional>
#include <vector>

enum ExecutableType
{
    EXECUTABLE_TYPE_USER_PRX,
    EXECUTABLE_TYPE_KERNEL_PRX,
    EXECUTABLE_TYPE_PBP
};

enum ErrorTypes
{
    NO_ERROR,
    ERROR_ALREADY_PACKED,
    ERROR_NOT_PRX,
    ERROR_NO_MODULEINFO,
    ERROR_MIXED_PRIVILEGES,
    ERROR_KERNEL_PBP,
    ERROR_NO_SEGMENTS,
    ERROR_NO_BSS_SECTION,
    ERROR_GZIP_COMPRESSION
};

using ExecBuffer = std::vector<char>;
using TagHandler = std::function<unsigned int(ExecutableType type)>;

int pack_executable(ExecBuffer& executable, TagHandler psptagHandler, TagHandler oetagHandler);

#endif // PACKEXEC_H_
