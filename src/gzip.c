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

#include <zlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

z_stream z;

/* Table of CRCs of all 8-bit messages. */
unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
int crc_table_computed = 0;

/* Make the table for a fast CRC. */
void make_crc_table(void)
{
  unsigned long c;
  int n, k;

  for (n = 0; n < 256; n++) {
    c = (unsigned long) n;
    for (k = 0; k < 8; k++) {
      if (c & 1) {
        c = 0xedb88320L ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
    crc_table[n] = c;
  }
  crc_table_computed = 1;
}

/*
   Update a running crc with the bytes buf[0..len-1] and return
 the updated crc. The crc should be initialized to zero. Pre- and
 post-conditioning (one's complement) is performed within this
 function so it shouldn't be done by the caller. Usage example:

   unsigned long crc = 0L;

   while (read_buffer(buffer, length) != EOF) {
     crc = update_crc(crc, buffer, length);
   }
   if (crc != original_crc) error();
*/
unsigned long update_crc(unsigned long crc,
                unsigned char *buf, int len)
{
  unsigned long c = crc ^ 0xffffffffL;
  int n;

  if (!crc_table_computed)
    make_crc_table();
  for (n = 0; n < len; n++) {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }
  return c ^ 0xffffffffL;
}

/* Return the CRC of the bytes buf[0..len-1]. */
unsigned long getCrc32(unsigned char *buf, int len)
{
  return update_crc(0L, buf, len);
}

int gzipGetMaxCompressedSize( int nLenSrc ) 
{
    int n16kBlocks = (nLenSrc+16383) / 16384;
    return ( nLenSrc + 6 + (n16kBlocks*5) + 18);
}

int DeflateCompress(void *outbuf, int outsize, void *inbuf, int insize)
{
	int res;
	memset(&z, 0, sizeof(z_stream));

	z.zalloc = Z_NULL;
	z.zfree  = Z_NULL;
	z.opaque = Z_NULL;

	if (deflateInit2(&z, 9, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		return -1;

	z.next_out  = outbuf;
	z.avail_out = outsize;
	z.next_in   = inbuf;
	z.avail_in  = insize;

	if (deflate(&z, Z_FINISH) != Z_STREAM_END)
		return -2;

	res = outsize - z.avail_out;

	if (deflateEnd(&z) != Z_OK)
		return -3;

	return res;
}

int UncompressData( const u8* abSrc, int nLenSrc, u8* abDst, int nLenDst )
{
    z_stream zInfo ={0};
    zInfo.total_in=  zInfo.avail_in=  nLenSrc;
    zInfo.total_out= zInfo.avail_out= nLenDst;
    zInfo.next_in= (u8*)abSrc;
    zInfo.next_out= abDst;

    int nErr, nRet= -1;
    nErr= inflateInit( &zInfo );            
    if ( nErr == Z_OK ) {
        nErr= inflate( &zInfo, Z_FINISH );    
        if ( nErr == Z_STREAM_END ) {
            nRet= zInfo.total_out;
        }
    }
    deflateEnd( &zInfo );   
    return( nRet );
}

int gzipCompress(void *outbuffer, u32 outsize, void *inbuffer, u32 insize)
{
	/* cast variables */
	u8 *outdata = (u8 *)outbuffer;
	
	/* minimum size for gzip */
	if (outsize < 18)
	{
		return -1;
	}
	
	/* fill in structure */
	memset(outdata, 0, 10);
	
	/* default gzip info */
	outdata[0] = 0x1F;
	outdata[1] = 0x8B;
	outdata[2] = 0x08;
	outdata[8] = 0x02;
	outdata[9] = 0x0B;
	
	/* get the crc32 */
	u32 crc32 = getCrc32(inbuffer, insize);
	
	/* deflate compress */
	int res = DeflateCompress(outdata + 10, outsize - 18, inbuffer, insize);
	
	/* check for error */
	if (res < 0)
	{
		return res;
	}
	
	/* check if there is enough size */
	if ((outsize - res - 10) < 8)
	{
		/* there is not enough size ): */
		return -2;
	}
	
	/* pwn */
	memcpy(outdata + 10 + res, &crc32, 4);
	memcpy(outdata + 10 + res + 4, &insize, 4);
	
	/* return size */
	return res + 18;
}
