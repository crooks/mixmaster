
/* $Id: compress.c,v 1.1 2002/08/28 20:06:49 rabbi Exp $
 * $Log: compress.c,v $
 * Revision 1.1  2002/08/28 20:06:49  rabbi
 * Initial revision
 *
 * Revision 2.4  1999/01/19  02:28:13  um
 * *** empty log message ***
 *
 * Revision 2.3  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.2  1998/04/13  23:22:29  um
 * re-indented.
 *
 *
 * compress.c    0.0 1996-11-26 um
 *
 *      (c) Copyright 1996 by Ulf Moeller. All right reserved.
 *      The author assumes no liability for damages resulting from the
 *      use of this software, even if the damage results from defects in
 *      this software. No warranty is expressed or implied.
 *
 *      This software is being distributed under the GNU Public Licence,
 *      see the file GNU.license for more details.
 */

/* Parts of this file taken from zlib:

   Copyright (C) 1995-1996 Jean-loup Gailly and Mark Adler

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
   2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
   3. This notice may not be removed or altered from any source distribution.
 */

#include <stdio.h>
#include "mix.h"

#ifdef USE_ZLIB
#include "zlib.h"

static int gz_magic[2] =
{0x1f, 0x8b};			/* gzip magic header */

/* gzip flag byte */
#define ASCII_FLAG   0x01	/* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02	/* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04	/* bit 2 set: extra field present */
#define ORIG_NAME    0x08	/* bit 3 set: original file name present */
#define COMMENT      0x10	/* bit 4 set: file comment present */
#define RESERVED     0xE0	/* bits 5..7: reserved */

byte *
gzheader (byte * b, int k)
{
  byte *p;
  unsigned int len;

  if (b[2] != Z_DEFLATED || (b[3] & RESERVED) != 0)
    {
      fprintf (errlog, "Unknown compression format.\n");
      return NULL;
    }
  p = b + 10;
  k -= 10;
  if ((b[3] & EXTRA_FIELD) != 0)
    {
      len = (unsigned int) b[11] + ((unsigned int) b[12] << 8);
      p += 2;
      k -= 2;
      while (len-- != 0 && --k > 0)
	p++;
    }
  if ((b[3] & ORIG_NAME) != 0)
    {
      while (*p != 0 && --k > 0)
	p++;
      p++;
    }
  if ((b[3] & COMMENT) != 0)
    {
      while (*p != 0 && --k > 0)
	p++;
      p++;
    }
  if ((b[3] & HEAD_CRC) != 0)
    p += 2;
  return p;
}

int
uncompress_b2file (byte * b, int len, FILE * out)
{
  z_stream s;
  char outbuf[4096];
  byte *p;
  int err;

  if (len < 2 || b[0] != gz_magic[0] || b[1] != gz_magic[1])
    {
      fwrite (b, 1, len, out);
      return 0;
    }

  s.zalloc = (alloc_func) 0;
  s.zfree = (free_func) 0;
  s.opaque = (voidpf) 0;

  p = gzheader (b, len);
  if (p == NULL)
    return -1;
  s.next_in = p;
  s.avail_in = len - (p - b);
  s.next_out = NULL;

  if (inflateInit2 (&s, -MAX_WBITS) != Z_OK)
    return (-1);

  s.next_out = outbuf;
  s.avail_out = sizeof (outbuf);

  while ((err = inflate (&s, Z_PARTIAL_FLUSH)) == Z_OK)
    {
      fwrite (outbuf, 1, sizeof (outbuf) - s.avail_out, out);
      s.next_out = outbuf;
      s.avail_out = sizeof (outbuf);
    }
  fwrite (outbuf, 1, sizeof (outbuf) - s.avail_out, out);
  if ((err=inflateEnd (&s)) != Z_OK)
    {
      fprintf (errlog, "Decompression error %d.\n",err);
      return (-1);
    }
  return 0;
}

int
uncompress_file2file (FILE * in, FILE * out)
{
  z_stream s;
  byte b[2048];
  int len;
  char outbuf[4096];
  byte *p;
  int err;

  len = fread (b, 1, sizeof (b), in);

  if (len < 2 || b[0] != gz_magic[0] || b[1] != gz_magic[1])
    {
      fwrite (b, 1, len, out);
      while ((len = fread (b, 1, sizeof (b), in)) != 0)
	fwrite (b, 1, len, out);
      return 0;
    }

  s.zalloc = (alloc_func) 0;
  s.zfree = (free_func) 0;
  s.opaque = (voidpf) 0;

  p = gzheader (b, len);
  if (p == NULL)
    return (-1);
  s.next_in = p;
  s.avail_in = len - (p - b);
  s.next_out = NULL;

  if (inflateInit2 (&s, -MAX_WBITS) != Z_OK)
    return (-1);

  s.next_out = outbuf;
  s.avail_out = sizeof (outbuf);

  while ((err = inflate (&s, Z_PARTIAL_FLUSH)) == Z_OK)
    {
      fwrite (outbuf, 1, sizeof (outbuf) - s.avail_out, out);
      s.next_out = outbuf;
      s.avail_out = sizeof (outbuf);
      if (s.avail_in == 0)
	{
	  s.next_in = b;
	  s.avail_in = fread (b, 1, sizeof (b), in);
	}
    }
  fwrite (outbuf, 1, sizeof (outbuf) - s.avail_out, out);
  if ((err=inflateEnd (&s) != Z_OK))
    {
      fprintf (errlog, "Decompression error %d.\n", err);
      return (-1);
    }
  return 0;
}

int
compressed_buf (BUFFER * b, long offset)
{
  if (b->length < offset + 2 || b->message[offset] != gz_magic[0] ||
      b->message[offset + 1] != gz_magic[1])
    return 0;
  else
    return 1;
}

int
uncompress_buf2buf (BUFFER * in, BUFFER * out, long offset)
{
  z_stream s;
  char outbuf[4096];
  byte *p;
  int err;

  if (!compressed_buf (in, offset))
    return 0;			/* not compressed */

  add_to_buffer (out, in->message, offset);

  s.zalloc = (alloc_func) 0;
  s.zfree = (free_func) 0;
  s.opaque = (voidpf) 0;

  p = gzheader (in->message + offset, in->length);
  if (p == NULL)
    return -1;
  s.next_in = p;
  s.avail_in = in->length - (p - in->message);
  s.next_out = NULL;

  if (inflateInit2 (&s, -MAX_WBITS) != Z_OK)
    return (-1);

  s.next_out = outbuf;
  s.avail_out = sizeof (outbuf);

  while ((err = inflate (&s, Z_PARTIAL_FLUSH)) == Z_OK)
    {
      add_to_buffer (out, outbuf, sizeof (outbuf) - s.avail_out);
      s.next_out = outbuf;
      s.avail_out = sizeof (outbuf);
    }
  add_to_buffer (out, outbuf, sizeof (outbuf) - s.avail_out);
  if ((err=inflateEnd (&s) != Z_OK))
    {
      fprintf (errlog, "Decompression error. %d\n",err);
      return (-1);
    }
  return 1;			/* compressed */
}


int
compress_buf2buf (BUFFER * in, BUFFER * out, long offset)
{
  z_stream s;
  int err;
  char outbuf[4096];

  if (compressed_buf (in, offset))
    {
      /* is already compressed */
      add_to_buffer (out, in->message, in->length);
      return 0;
    }

  add_to_buffer (out, in->message, offset);

  s.zalloc = (alloc_func) 0;
  s.zfree = (free_func) 0;
  s.opaque = (voidpf) 0;
  s.next_in = NULL;

  sprintf (outbuf, "%c%c%c%c%c%c%c%c%c%c", gz_magic[0], gz_magic[1],
	   Z_DEFLATED, 0 /*flags */ , 0, 0, 0, 0 /*time */ , 0 /*xflags */ ,
	   3 /* Unix */ );
  add_to_buffer (out, outbuf, 10);

  if (deflateInit2 (&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
		    8, 0) != Z_OK)
    return 0;

  s.next_in = in->message + offset;
  s.avail_in = in->length - offset;
  s.next_out = outbuf;
  s.avail_out = sizeof (outbuf);

  while ((err = deflate (&s, Z_FINISH)) == Z_OK)
    {
      add_to_buffer (out, outbuf, sizeof (outbuf) - s.avail_out);
      s.next_out = outbuf;
      s.avail_out = sizeof (outbuf);
    }
  add_to_buffer (out, outbuf, sizeof (outbuf) - s.avail_out);
  if (deflateEnd (&s) != Z_OK || err != Z_STREAM_END)
    return 0;
  return 1;
}

#else /* !USE_ZLIB */

uncompress_b2file (byte * b, int len, FILE * out)
{
  fwrite (b, 1, len, out);
  return 0;
}

int
uncompress_file2file (FILE * in, FILE * out)
{
  byte b[2048];
  int len;

  while ((len = fread (b, 1, sizeof (b), in)) != 0)
    fwrite (b, 1, len, out);
  return 0;
}

#endif /* USE_ZLIB */
