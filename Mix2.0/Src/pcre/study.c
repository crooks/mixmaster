/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/*
This is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language. See
the file Tech.Notes for some information on the internals.

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
*/


/* Include the internals header, which itself includes Standard C headers plus
the external pcre header. */

#include "internal.h"



/*************************************************
*          Create bitmap of starting chars       *
*************************************************/

/* This function scans a compiled unanchored expression and attempts to build a
bitmap of the set of initial characters. If it can't, it returns FALSE. As time
goes by, we may be able to get more clever at doing this.

Arguments:
  code         points to an expression
  start_bits   points to a 32-byte table, initialized to 0

Returns:       TRUE if table built, FALSE otherwise
*/

static BOOL
set_start_bits(const uschar *code, uschar *start_bits)
{
register int c;

do
  {
  const uschar *tcode = code + 3;
  BOOL try_next = TRUE;

  while (try_next)
    {
    try_next = FALSE;

    if ((int)*tcode >= OP_BRA || *tcode == OP_ASSERT)
      {
      if (!set_start_bits(tcode, start_bits)) return FALSE;
      }

    else switch(*tcode)
      {
      default:
      return FALSE;

      /* BRAZERO does the bracket, but carries on. */

      case OP_BRAZERO:
      case OP_BRAMINZERO:
      if (!set_start_bits(++tcode, start_bits)) return FALSE;
      do tcode += (tcode[1] << 8) + tcode[2]; while (*tcode == OP_ALT);
      tcode += 3;
      try_next = TRUE;
      break;

      /* Single-char * or ? sets the bit and tries the next item */

      case OP_STAR:
      case OP_MINSTAR:
      case OP_QUERY:
      case OP_MINQUERY:
      start_bits[tcode[1]/8] |= (1 << (tcode[1]&7));
      tcode += 2;
      try_next = TRUE;
      break;

      /* Single-char upto sets the bit and tries the next */

      case OP_UPTO:
      case OP_MINUPTO:
      start_bits[tcode[3]/8] |= (1 << (tcode[3]&7));
      tcode += 4;
      try_next = TRUE;
      break;

      /* At least one single char sets the bit and stops */

      case OP_EXACT:       /* Fall through */
      tcode++;

      case OP_CHARS:       /* Fall through */
      tcode++;

      case OP_PLUS:
      case OP_MINPLUS:
      start_bits[tcode[1]/8] |= (1 << (tcode[1]&7));
      break;

      /* Single character type sets the bits and stops */

      case OP_NOT_DIGIT:
      for (c = 0; c < 32; c++) start_bits[c] |= ~pcre_cbits[c+cbit_digit];
      break;

      case OP_DIGIT:
      for (c = 0; c < 32; c++) start_bits[c] |= pcre_cbits[c+cbit_digit];
      break;

      case OP_NOT_WHITESPACE:
      for (c = 0; c < 32; c++) start_bits[c] |= ~pcre_cbits[c+cbit_space];
      break;

      case OP_WHITESPACE:
      for (c = 0; c < 32; c++) start_bits[c] |= pcre_cbits[c+cbit_space];
      break;

      case OP_NOT_WORDCHAR:
      for (c = 0; c < 32; c++)
        start_bits[c] |= ~(pcre_cbits[c] | pcre_cbits[c+cbit_word]);
      break;

      case OP_WORDCHAR:
      for (c = 0; c < 32; c++)
        start_bits[c] |= (pcre_cbits[c] | pcre_cbits[c+cbit_word]);
      break;

      /* One or more character type fudges the pointer and restarts, knowing
      it will hit a single character type and stop there. */

      case OP_TYPEPLUS:
      case OP_TYPEMINPLUS:
      tcode++;
      try_next = TRUE;
      break;

      case OP_TYPEEXACT:
      tcode += 3;
      try_next = TRUE;
      break;

      /* Zero or more repeats of character types set the bits and then
      try again. */

      case OP_TYPEUPTO:
      case OP_TYPEMINUPTO:
      tcode += 2;               /* Fall through */

      case OP_TYPESTAR:
      case OP_TYPEMINSTAR:
      case OP_TYPEQUERY:
      case OP_TYPEMINQUERY:
      switch(tcode[1])
        {
        case OP_NOT_DIGIT:
        for (c = 0; c < 32; c++) start_bits[c] |= ~pcre_cbits[c+cbit_digit];
        break;

        case OP_DIGIT:
        for (c = 0; c < 32; c++) start_bits[c] |= pcre_cbits[c+cbit_digit];
        break;

        case OP_NOT_WHITESPACE:
        for (c = 0; c < 32; c++) start_bits[c] |= ~pcre_cbits[c+cbit_space];
        break;

        case OP_WHITESPACE:
        for (c = 0; c < 32; c++) start_bits[c] |= pcre_cbits[c+cbit_space];
        break;

        case OP_NOT_WORDCHAR:
        for (c = 0; c < 32; c++)
          start_bits[c] |= ~(pcre_cbits[c] | pcre_cbits[c+cbit_word]);
        break;

        case OP_WORDCHAR:
        for (c = 0; c < 32; c++)
          start_bits[c] |= (pcre_cbits[c] | pcre_cbits[c+cbit_word]);
        break;
        }

      tcode += 2;
      try_next = TRUE;
      break;

      /* Character class: set the bits and either carry on or not,
      according to the repeat count. */

      case OP_CLASS:
      case OP_NEGCLASS:
        {
        tcode++;
        for (c = 0; c < 32; c++) start_bits[c] |= tcode[c];
        tcode += 32;
        switch (*tcode)
          {
          case OP_CRSTAR:
          case OP_CRMINSTAR:
          case OP_CRQUERY:
          case OP_CRMINQUERY:
          tcode++;
          try_next = TRUE;
          break;

          case OP_CRRANGE:
          case OP_CRMINRANGE:
          if (((tcode[1] << 8) + tcode[2]) == 0)
            {
            tcode += 5;
            try_next = TRUE;
            }
          break;
          }
        }
      break; /* End of class handling */

      }      /* End of switch */
    }        /* End of try_next loop */

  code += (code[1] << 8) + code[2];   /* Advance to next branch */
  }
while (*code == OP_ALT);
return TRUE;
}



/*************************************************
*          Study a compiled expression           *
*************************************************/

/* This function is handed a compiled expression that it must study to produce
information that will speed up the matching. It returns a pcre_extra block
which then gets handed back to pcre_exec().

Arguments:
  re        points to the compiled expression
  options   contains option bits
  errorptr  points to where to place error messages;
            set NULL unless error

Returns:    pointer to a pcre_extra block,
            NULL on error or if no optimization possible
*/

pcre_extra *
pcre_study(const pcre *external_re, int options, const char **errorptr)
{
BOOL caseless;
uschar start_bits[32];
real_pcre_extra *extra;
const real_pcre *re = (const real_pcre *)external_re;

*errorptr = NULL;

if (re == NULL || re->magic_number != MAGIC_NUMBER)
  {
  *errorptr = "argument is not a compiled regular expression";
  return NULL;
  }

if ((options & ~PUBLIC_STUDY_OPTIONS) != 0)
  {
  *errorptr = "unknown or incorrect option bit(s) set";
  return NULL;
  }

/* Caseless can either be from the compiled regex or from options. */

caseless = ((re->options | options) & PCRE_CASELESS) != 0;

/* For an anchored pattern, or an unchored pattern that has a first char, or a
multiline pattern that matches only at "line starts", no further processing at
present. */

if ((re->options & (PCRE_ANCHORED|PCRE_FIRSTSET|PCRE_STARTLINE)) != 0)
  return NULL;

/* See if we can find a fixed set of initial characters for the pattern. */

memset(start_bits, 0, 32 * sizeof(uschar));
if (!set_start_bits(re->code, start_bits)) return NULL;

/* If this studying is caseless, scan the created bit map and duplicate the
bits for any letters. */

if (caseless)
  {
  register int c;
  for (c = 0; c < 256; c++)
    {
    if ((start_bits[c/8] & (1 << (c&7))) != 0 &&
        (pcre_ctypes[c] & ctype_letter) != 0)
      {
      int d = pcre_fcc[c];
      start_bits[d/8] |= (1 << (d&7));
      }
    }
  }

/* Get an "extra" block and put the information therein. */

extra = (real_pcre_extra *)(pcre_malloc)(sizeof(real_pcre_extra));

if (extra == NULL)
  {
  *errorptr = "failed to get memory";
  return NULL;
  }

extra->options = PCRE_STUDY_MAPPED | (caseless? PCRE_STUDY_CASELESS : 0);
memcpy(extra->start_bits, start_bits, sizeof(start_bits));

return (pcre_extra *)extra;
}

/* End of study.c */
