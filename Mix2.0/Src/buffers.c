/* $Id: buffers.c,v 1.1 2002/08/28 20:06:49 rabbi Exp $
 * $Log: buffers.c,v $
 * Revision 1.1  2002/08/28 20:06:49  rabbi
 * Initial revision
 *
 * Revision 2.4  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.3  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 *
 *     buffers.c            1997-08-15 um
 *
 *     buffers.c            1997-06-17 um
 *       use memset.
 *
 *     buffers.c            1997-06-10 um
 *       new function pad_buffer
 *
 *     buffers.c            1997-06-02 um
 *       new function str_to_buffer
 *
 *     buffers.c            1997-05-30 um
 *       new function write_buffer
 *
 *     buffers.c            1997-05-29 um
 *       minor changes.
 *
 *      Some trivial modifications made to buffers.c by Lance Cottrell 4/23/95
 *
 * @(#)buffers.c        1.7 6/29/94
 *
 *      (c) Copyright 1993-1994 by Mark Grant. All right reserved.
 *      The author assumes no liability for damages resulting from the
 *      use of this software, even if the damage results from defects in
 *      this software. No warranty is expressed or implied.
 *
 *      This software is being distributed under the GNU Public Licence,
 *      see the file GNU.license for more details.
 *
 *                      - Mark Grant (mark@unicorn.com) 29/6/94
 *
 */

#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "mix.h"

void
add_to_buffer (BUFFER * buffer, const byte * mess, int len)
{
  assert (len >= 0);

  if (!buffer->size)
    {
      if ((buffer->message = (byte *) malloc (QUANTA)) != NULL)
	buffer->size = QUANTA;
    }
  if (buffer->length + len >= buffer->size)
    {
      buffer->size = (buffer->size + len + QUANTA) / QUANTA;
      buffer->size *= QUANTA;
      buffer->message = (byte *) realloc (buffer->message,
					  buffer->size);
    }
  if (mess)
    memcpy (buffer->message + buffer->length, mess, len);
  else
    memset (buffer->message + buffer->length, 0, len);
  buffer->length += len;

  buffer->message[buffer->length] = 0;
}

void
str_to_buffer (BUFFER * buffer, const char *s)
{
  add_to_buffer (buffer, s, strlen (s));
}

BUFFER *
new_buffer (void)
{
  BUFFER *b;

  b = (BUFFER *) malloc (sizeof (BUFFER));
  b->message = 0;
  b->size = 0;
  b->length = 0;

  return b;
}

void
free_buffer (BUFFER * b)
{
  if (b->message && b->size)
    {
      memset (b->message, 0, b->size);
      free (b->message);
    }
  free (b);
}

void
clear_buffer (BUFFER * b)
{
  if (b->message && b->size)
    memset (b->message, 0, b->size);
  b->length = 0;
}

void
reset_buffer (BUFFER * b)
{
  if (b->message && b->size)
    {
      memset (b->message, 0, b->size);
      free (b->message);
    }
  b->size = 0;
  b->length = 0;
}

int
write_buffer (BUFFER * buff, FILE * f)
{
  return (fwrite (buff->message, 1, buff->length, f));
}

void
pad_buffer (BUFFER * buffer, int len)
{
  byte *b;
  int n;

  n = len - buffer->length;
  assert (n >= 0);
  if (n == 0)
    return;
  b = malloc (n);
  our_randombytes (b, n);
  add_to_buffer (buffer, b, n);
  free (b);
}
