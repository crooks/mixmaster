
/* $Id: type1.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: type1.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.2  1998/04/13  23:22:29  um
 * re-indented.
 *
 *
 * type1.c            1997-06-16 um
 * type1.c            1996-11-27 um
 *      trivial modifications.
 *
 * type1.c        1.0 4/23/95
 *
 *      (c) Copyright 1995 by Lance Cottrell. All right reserved.
 *      The author assumes no liability for damages resulting from the
 *      use of this software, even if the damage results from defects in
 *      this software. No warranty is expressed or implied.
 *
 *      This software is being distributed under the GNU Public Licence,
 *      see the file GNU.license for more details.
 *
 *                      - Lance Cottrell (loki@obscura.com) 4/23/95
 *
 */

#include "mix.h"
#include <stdio.h>

/*
   The purpose of this code is just to send
   the type 1 message to an apropriate
   program. No processing of the message is done
 */
int
type_1 (const char *filename)
{
  int len;
  char chunk[1024];
  FILE *fptr, *pptr;

  if ((fptr = open_mix_file (filename, "r")) == NULL)
    return (1);
  if ((pptr = open_pipe (TYPE1, "w")) == NULL)
    return (2);
  while ((len = fread (chunk, 1, sizeof (chunk), fptr)) > 0)
    fwrite (chunk, 1, len, pptr);
  fclose (fptr);
  close_pipe (pptr);
  if (len == 0)
    return (0);
  return (1);
}
