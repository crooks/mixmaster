/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/*
PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

Written by: Philip Hazel <ph10@cam.ac.uk>

           Copyright (c) 1998 University of Cambridge

-----------------------------------------------------------------------------
Permission is granted to anyone to use this software for any purpose on any
computer system, and to redistribute it freely, subject to the following
restrictions:

1. This software is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

2. The origin of this software must not be misrepresented, either by
   explicit claim or by omission.

3. Altered versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
-----------------------------------------------------------------------------

See the file Tech.Notes for some information on the internals.
*/


/* This is a support program to generate the file chartables.c, containing
character tables of various kinds. They are built according to the local C
locale. */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "internal.h"

int main(void)
{
int i;
unsigned char cbits[cbit_length];

printf(
  "/*************************************************\n"
  "*      Perl-Compatible Regular Expressions       *\n"
  "*************************************************/\n\n"
  "/* This file is automatically written by the makechartables auxiliary \n"
  "program. If you edit it by hand, you might like to edit the Makefile to \n"
  "prevent its ever being regenerated. */\n\n"
  "/* This table is a lower casing table. */\n\n"
  "unsigned char pcre_lcc[] = {\n");

printf("  ");
for (i = 0; i < 256; i++)
  {
  if ((i & 7) == 0 && i != 0) printf("\n  ");
  printf("%3d", tolower(i));
  if (i != 255) printf(",");
  }
printf(" };\n\n");

printf(
  "/* This table is a case flipping table. */\n\n"
  "unsigned char pcre_fcc[] = {\n");

printf("  ");
for (i = 0; i < 256; i++)
  {
  if ((i & 7) == 0 && i != 0) printf("\n  ");
  printf("%3d", islower(i)? toupper(i) : tolower(i));
  if (i != 255) printf(",");
  }
printf(" };\n\n");

printf(
  "/* This table contains bit maps for digits, letters, 'word' chars, and\n"
  "white space. Each map is 32 bytes long and the bits run from the least\n"
  "significant end of each byte. */\n\n"
  "unsigned char pcre_cbits[] = {\n");

memset(cbits, 0, sizeof(cbits));

for (i = 0; i < 256; i++)
  {
  if (isdigit(i)) cbits[cbit_digit  + i/8] |= 1 << (i&7);
  if (isalpha(i)) cbits[cbit_letter + i/8] |= 1 << (i&7);
  if (isalnum(i) || i == '_')
                  cbits[cbit_word   + i/8] |= 1 << (i&7);
  if (isspace(i)) cbits[cbit_space  + i/8] |= 1 << (i&7);
  }

printf("  ");
for (i = 0; i < cbit_length; i++)
  {
  if ((i & 7) == 0 && i != 0)
    {
    if ((i & 31) == 0) printf("\n");
    printf("\n  ");
    }
  printf("0x%02x", cbits[i]);
  if (i != cbit_length - 1) printf(",");
  }
printf(" };\n\n");

printf(
  "/* This table identifies various classes of character by individual bits:\n"
  "  0x%02x   white space character\n"
  "  0x%02x   letter\n"
  "  0x%02x   decimal digit\n"
  "  0x%02x   hexadecimal digit\n"
  "  0x%02x   alphanumeric or '_'\n"
  "  0x%02x   regular expression metacharacter or binary zero\n*/\n\n",
  ctype_space, ctype_letter, ctype_digit, ctype_xdigit, ctype_word,
  ctype_meta);

printf("unsigned char pcre_ctypes[] = {\n");

printf("  ");
for (i = 0; i < 256; i++)
  {
  int x = 0;
  if (isspace(i)) x += ctype_space;
  if (isalpha(i)) x += ctype_letter;
  if (isdigit(i)) x += ctype_digit;
  if (isxdigit(i)) x += ctype_xdigit;
  if (isalnum(i) || i == '_') x += ctype_word;
  if (strchr("*+?{^.$|()[", i) != 0) x += ctype_meta;

  if ((i & 7) == 0 && i != 0)
    {
    printf(" /* ");
    if (isprint(i-8)) printf(" %c -", i-8);
      else printf("%3d-", i-8);
    if (isprint(i-1)) printf(" %c ", i-1);
      else printf("%3d", i-1);
    printf(" */\n  ");
    }
  printf("0x%02x", x);
  if (i != 255) printf(",");
  }

printf("};/* ");
if (isprint(i-8)) printf(" %c -", i-8);
  else printf("%3d-", i-8);
if (isprint(i-1)) printf(" %c ", i-1);
  else printf("%3d", i-1);
printf(" */\n\n/* End of chartables.c */\n");

return 0;
}

/* End of maketables.c */
