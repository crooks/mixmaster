/*************************************************
*             PCRE testing program               *
*************************************************/

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Use the internal info for displaying the results of pcre_study(). */

#include "internal.h"
#include "pcreposix.h"

#ifndef CLOCKS_PER_SEC
#ifdef CLK_TCK
#define CLOCKS_PER_SEC CLK_TCK
#else
#define CLOCKS_PER_SEC 100
#endif
#endif


static FILE *outfile;
static int log_store = 0;



/* Debugging function to print the internal form of the regex. This is the same
code as contained in pcre.c under the DEBUG macro. */

static const char *OP_names[] = {
  "End", "\\A", "\\B", "\\b", "\\D", "\\d",
  "\\S", "\\s", "\\W", "\\w", "Cut", "\\Z", "^", "$", "Any", "chars",
  "not",
  "*", "*?", "+", "+?", "?", "??", "{", "{", "{",
  "*", "*?", "+", "+?", "?", "??", "{", "{", "{",
  "*", "*?", "+", "+?", "?", "??", "{", "{", "{",
  "*", "*?", "+", "+?", "?", "??", "{", "{",
  "class", "negclass", "Ref",
  "Alt", "Ket", "KetRmax", "KetRmin", "Assert", "Assert not", "Once",
  "Brazero", "Braminzero", "Bra"
};


static void print_internals(pcre *re)
{
unsigned char *code = ((real_pcre *)re)->code;

printf("------------------------------------------------------------------\n");

for(;;)
  {
  int c;
  int charlength;

  printf("%3d ", code - ((real_pcre *)re)->code);

  if (*code >= OP_BRA)
    {
    printf("%3d Bra %d", (code[1] << 8) + code[2], *code - OP_BRA);
    code += 2;
    }

  else switch(*code)
    {
    case OP_END:
    printf("    %s\n", OP_names[*code]);
    printf("------------------------------------------------------------------\n");
    return;

    case OP_CHARS:
    charlength = *(++code);
    printf("%3d ", charlength);
    while (charlength-- > 0)
      if (isprint(c = *(++code))) printf("%c", c); else printf("\\x%02x", c);
    break;

    case OP_KETRMAX:
    case OP_KETRMIN:
    case OP_ALT:
    case OP_KET:
    case OP_ASSERT:
    case OP_ASSERT_NOT:
    case OP_ONCE:
    printf("%3d %s", (code[1] << 8) + code[2], OP_names[*code]);
    code += 2;
    break;

    case OP_STAR:
    case OP_MINSTAR:
    case OP_PLUS:
    case OP_MINPLUS:
    case OP_QUERY:
    case OP_MINQUERY:
    case OP_TYPESTAR:
    case OP_TYPEMINSTAR:
    case OP_TYPEPLUS:
    case OP_TYPEMINPLUS:
    case OP_TYPEQUERY:
    case OP_TYPEMINQUERY:
    if (*code >= OP_TYPESTAR)
      printf("    %s", OP_names[code[1]]);
    else if (isprint(c = code[1])) printf("    %c", c);
      else printf("    \\x%02x", c);
    printf("%s", OP_names[*code++]);
    break;

    case OP_EXACT:
    case OP_UPTO:
    case OP_MINUPTO:
    if (isprint(c = code[3])) printf("    %c{", c);
      else printf("    \\x%02x{", c);
    if (*code != OP_EXACT) printf(",");
    printf("%d}", (code[1] << 8) + code[2]);
    if (*code == OP_MINUPTO) printf("?");
    code += 3;
    break;

    case OP_TYPEEXACT:
    case OP_TYPEUPTO:
    case OP_TYPEMINUPTO:
    printf("    %s{", OP_names[code[3]]);
    if (*code != OP_TYPEEXACT) printf("0,");
    printf("%d}", (code[1] << 8) + code[2]);
    if (*code == OP_TYPEMINUPTO) printf("?");
    code += 3;
    break;

    case OP_NOT:
    if (isprint(c = *(++code))) printf("    [^%c]", c);
      else printf("    [^\\x%02x]", c);
    break;

    case OP_NOTSTAR:
    case OP_NOTMINSTAR:
    case OP_NOTPLUS:
    case OP_NOTMINPLUS:
    case OP_NOTQUERY:
    case OP_NOTMINQUERY:
    if (isprint(c = code[1])) printf("    [^%c]", c);
      else printf("    [^\\x%02x]", c);
    printf("%s", OP_names[*code++]);
    break;

    case OP_NOTEXACT:
    case OP_NOTUPTO:
    case OP_NOTMINUPTO:
    if (isprint(c = code[3])) printf("    [^%c]{", c);
      else printf("    [^\\x%02x]{", c);
    if (*code != OP_NOTEXACT) printf(",");
    printf("%d}", (code[1] << 8) + code[2]);
    if (*code == OP_NOTMINUPTO) printf("?");
    code += 3;
    break;

    case OP_REF:
    printf("    \\%d", *(++code));
    code++;
    goto CLASS_REF_REPEAT;

    case OP_CLASS:
    case OP_NEGCLASS:
      {
      int i, min, max;
      if (*code++ == OP_CLASS) printf("    [");
        else printf("   ^[");

      for (i = 0; i < 256; i++)
        {
        if ((code[i/8] & (1 << (i&7))) != 0)
          {
          int j;
          for (j = i+1; j < 256; j++)
            if ((code[j/8] & (1 << (j&7))) == 0) break;
          if (i == '-' || i == ']') printf("\\");
          if (isprint(i)) printf("%c", i); else printf("\\x%02x", i);
          if (--j > i)
            {
            printf("-");
            if (j == '-' || j == ']') printf("\\");
            if (isprint(j)) printf("%c", j); else printf("\\x%02x", j);
            }
          i = j;
          }
        }
      printf("]");
      code += 32;

      CLASS_REF_REPEAT:

      switch(*code)
        {
        case OP_CRSTAR:
        case OP_CRMINSTAR:
        case OP_CRPLUS:
        case OP_CRMINPLUS:
        case OP_CRQUERY:
        case OP_CRMINQUERY:
        printf("%s", OP_names[*code]);
        break;

        case OP_CRRANGE:
        case OP_CRMINRANGE:
        min = (code[1] << 8) + code[2];
        max = (code[3] << 8) + code[4];
        if (max == 0) printf("{%d,}", min);
        else printf("{%d,%d}", min, max);
        if (*code == OP_CRMINRANGE) printf("?");
        code += 4;
        break;

        default:
        code--;
        }
      }
    break;

    /* Anything else is just a one-node item */

    default:
    printf("    %s", OP_names[*code]);
    break;
    }

  code++;
  printf("\n");
  }
}



/* Character string printing function. */

static void pchars(unsigned char *p, int length)
{
int c;
while (length-- > 0)
  if (isprint(c = *(p++))) fprintf(outfile, "%c", c);
    else fprintf(outfile, "\\x%02x", c);
}



/* Alternative malloc function, to test functionality and show the size of the
compiled re. */

static void *new_malloc(size_t size)
{
if (log_store) fprintf(outfile, "Store size request: %d\n", (int)size);
return malloc(size);
}



/* Read lines from named file or stdin and write to named file or stdout; lines
consist of a regular expression, in delimiters and optionally followed by
options, followed by a set of test data, terminated by an empty line. */

int main(int argc, char **argv)
{
FILE *infile = stdin;
int options = 0;
int study_options = 0;
int op = 1;
int timeit = 0;
int showinfo = 0;
int posix = 0;
int debug = 0;
int done = 0;
unsigned char buffer[30000];
unsigned char dbuffer[1024];

/* Static so that new_malloc can use it. */

outfile = stdout;

/* Scan options */

while (argc > 1 && argv[op][0] == '-')
  {
  if (strcmp(argv[op], "-s") == 0) log_store = 1;
  else if (strcmp(argv[op], "-t") == 0) timeit = 1;
  else if (strcmp(argv[op], "-i") == 0) showinfo = 1;
  else if (strcmp(argv[op], "-d") == 0) showinfo = debug = 1;
  else if (strcmp(argv[op], "-p") == 0) posix = 1;
  else
    {
    printf("*** Unknown option %s\n", argv[op]);
    return 1;
    }
  op++;
  argc--;
  }

/* Sort out the input and output files */

if (argc > 1)
  {
  infile = fopen(argv[op], "r");
  if (infile == NULL)
    {
    printf("** Failed to open %s\n", argv[op]);
    return 1;
    }
  }

if (argc > 2)
  {
  outfile = fopen(argv[op+1], "w");
  if (outfile == NULL)
    {
    printf("** Failed to open %s\n", argv[op+1]);
    return 1;
    }
  }

/* Set alternative malloc function */

pcre_malloc = new_malloc;

/* Heading line, then prompt for first re if stdin */

fprintf(outfile, "Testing Perl-Compatible Regular Expressions\n");
fprintf(outfile, "PCRE version %s\n\n", pcre_version());

/* Main loop */

while (!done)
  {
  pcre *re = NULL;
  pcre_extra *extra = NULL;
  regex_t preg;
  const char *error;
  unsigned char *p, *pp;
  int do_study = 0;
  int do_debug = 0;
  int do_posix = 0;
  int erroroffset, len, delimiter;

  if (infile == stdin) printf("  re> ");
  if (fgets((char *)buffer, sizeof(buffer), infile) == NULL) break;
  if (infile != stdin) fprintf(outfile, (char *)buffer);

  p = buffer;
  while (isspace(*p)) p++;
  if (*p == 0) continue;

  /* Get the delimiter and seek the end of the pattern; if is isn't
  complete, read more. */

  delimiter = *p++;

  if (isalnum(delimiter))
    {
    fprintf(outfile, "** Delimiter must not be alphameric\n");
    goto SKIP_DATA;
    }

  pp = p;

  for(;;)
    {
    while (*pp != 0 && *pp != delimiter) pp++;
    if (*pp != 0) break;

    len = sizeof(buffer) - (pp - buffer);
    if (len < 256)
      {
      fprintf(outfile, "** Expression too long - missing delimiter?\n");
      goto SKIP_DATA;
      }

    if (infile == stdin) printf("    > ");
    if (fgets((char *)pp, len, infile) == NULL)
      {
      fprintf(outfile, "** Unexpected EOF\n");
      done = 1;
      goto CONTINUE;
      }
    if (infile != stdin) fprintf(outfile, (char *)pp);
    }

  /* Terminate the pattern at the delimiter */

  *pp++ = 0;

  /* Look for options after final delimiter */

  options = 0;
  study_options = 0;
  while (*pp != 0)
    {
    switch (*pp++)
      {
      case 'i': options |= PCRE_CASELESS; break;
      case 'm': options |= PCRE_MULTILINE; break;
      case 's': options |= PCRE_DOTALL; break;
      case 'x': options |= PCRE_EXTENDED; break;
      case 'A': options |= PCRE_ANCHORED; break;
      case 'D': do_debug = 1; break;
      case 'E': options |= PCRE_DOLLAR_ENDONLY; break;
      case 'P': do_posix = 1; break;
      case 'S': do_study = 1; break;
      case 'I': study_options |= PCRE_CASELESS; break;
      case 'U': options |= PCRE_UNGREEDY; break;
      case 'X': options |= PCRE_EXTRA; break;
      case '\n': case ' ': break;
      default:
      fprintf(outfile, "** Unknown option '%c'\n", pp[-1]);
      goto SKIP_DATA;
      }
    }

  /* Handle compiling via the POSIX interface, which doesn't support the
  timing, showing, or debugging options. */

  if (posix || do_posix)
    {
    int rc;
    int cflags = 0;
    if ((options & PCRE_CASELESS) != 0) cflags |= REG_ICASE;
    if ((options & PCRE_MULTILINE) != 0) cflags |= REG_NEWLINE;
    rc = regcomp(&preg, (char *)p, cflags);

    /* Compilation failed; go back for another re, skipping to blank line
    if non-interactive. */

    if (rc != 0)
      {
      (void)regerror(rc, &preg, (char *)buffer, sizeof(buffer));
      fprintf(outfile, "Failed: POSIX code %d: %s\n", rc, buffer);
      goto SKIP_DATA;
      }
    }

  /* Handle compiling via the native interface */

  else
    {
    if (timeit)
      {
      register int i;
      clock_t time_taken;
      clock_t start_time = clock();
      for (i = 0; i < 4000; i++)
        {
        re = pcre_compile((char *)p, options, &error, &erroroffset);
        if (re != NULL) free(re);
        }
      time_taken = clock() - start_time;
      fprintf(outfile, "Compile time %.2f milliseconds\n",
        ((double)time_taken)/(4 * CLOCKS_PER_SEC));
      }

    re = pcre_compile((char *)p, options, &error, &erroroffset);

    /* Compilation failed; go back for another re, skipping to blank line
    if non-interactive. */

    if (re == NULL)
      {
      fprintf(outfile, "Failed: %s at offset %d\n", error, erroroffset);
      SKIP_DATA:
      if (infile != stdin)
        {
        for (;;)
          {
          if (fgets((char *)buffer, sizeof(buffer), infile) == NULL)
            {
            done = 1;
            goto CONTINUE;
            }
          len = (int)strlen((char *)buffer);
          while (len > 0 && isspace(buffer[len-1])) len--;
          if (len == 0) break;
          }
        fprintf(outfile, "\n");
        }
      continue;
      }

    /* Compilation succeeded; print data if required */

    if (showinfo || do_debug)
      {
      int first_char, count;

      if (debug || do_debug) print_internals(re);

      count = pcre_info(re, &options, &first_char);
      if (count < 0) fprintf(outfile,
        "Error %d while reading info\n", count);
      else
        {
        fprintf(outfile, "Identifying subpattern count = %d\n", count);
        if (options == 0) fprintf(outfile, "No options\n");
          else fprintf(outfile, "Options:%s%s%s%s%s%s%s%s\n",
            ((options & PCRE_ANCHORED) != 0)? " anchored" : "",
            ((options & PCRE_CASELESS) != 0)? " caseless" : "",
            ((options & PCRE_EXTENDED) != 0)? " extended" : "",
            ((options & PCRE_MULTILINE) != 0)? " multiline" : "",
            ((options & PCRE_DOTALL) != 0)? " dotall" : "",
            ((options & PCRE_DOLLAR_ENDONLY) != 0)? " dollar_endonly" : "",
            ((options & PCRE_EXTRA) != 0)? " extra" : "",
            ((options & PCRE_UNGREEDY) != 0)? " ungreedy" : "");
        if (first_char == -1)
          {
          fprintf(outfile, "First char at start or follows \\n\n");
          }
        else if (first_char < 0)
          {
          fprintf(outfile, "No first char\n");
          }
        else
          {
          if (isprint(first_char))
            fprintf(outfile, "First char = \'%c\'\n", first_char);
          else
            fprintf(outfile, "First char = %d\n", first_char);
          }
        }
      }

    /* If /S was present, study the regexp to generate additional info to
    help with the matching. */

    if (do_study)
      {
      if (timeit)
        {
        register int i;
        clock_t time_taken;
        clock_t start_time = clock();
        for (i = 0; i < 4000; i++)
          extra = pcre_study(re, study_options, &error);
        time_taken = clock() - start_time;
        if (extra != NULL) free(extra);
        fprintf(outfile, "  Study time %.2f milliseconds\n",
          ((double)time_taken)/(4 * CLOCKS_PER_SEC));
        }

      extra = pcre_study(re, study_options, &error);
      if (error != NULL)
        fprintf(outfile, "Failed to study: %s\n", error);
      else if (extra == NULL)
        fprintf(outfile, "Study returned NULL\n");

      /* This looks at internal information. A bit kludgy to do it this
      way, but it is useful for testing. */

      else if (showinfo || do_debug)
        {
        real_pcre_extra *xx = (real_pcre_extra *)extra;
        if ((xx->options & PCRE_STUDY_MAPPED) == 0)
          fprintf(outfile, "No starting character set\n");
        else
          {
          int i;
          int c = 24;
          fprintf(outfile, "Starting character set: ");
          for (i = 0; i < 256; i++)
            {
            if ((xx->start_bits[i/8] & (1<<(i%8))) != 0)
              {
              if (c > 75)
                {
                fprintf(outfile, "\n  ");
                c = 2;
                }
              if (isprint(i) && i != ' ')
                {
                fprintf(outfile, "%c ", i);
                c += 2;
                }
              else
                {
                fprintf(outfile, "\\x%02x ", i);
                c += 5;
                }
              }
            }
          fprintf(outfile, "\n");
          }
        }
      }
    }

  /* Read data lines and test them */

  for (;;)
    {
    unsigned char *q;
    int count, c;
    int offsets[30];
    int size_offsets = sizeof(offsets)/sizeof(int);

    options = 0;

    if (infile == stdin) printf("  data> ");
    if (fgets((char *)buffer, sizeof(buffer), infile) == NULL)
      {
      done = 1;
      goto CONTINUE;
      }
    if (infile != stdin) fprintf(outfile, (char *)buffer);

    len = (int)strlen((char *)buffer);
    while (len > 0 && isspace(buffer[len-1])) len--;
    buffer[len] = 0;
    if (len == 0) break;

    p = buffer;
    while (isspace(*p)) p++;

    q = dbuffer;
    while ((c = *p++) != 0)
      {
      int i = 0;
      int n = 0;
      if (c == '\\') switch ((c = *p++))
        {
        case 'a': c =    7; break;
        case 'b': c = '\b'; break;
        case 'e': c =   27; break;
        case 'f': c = '\f'; break;
        case 'n': c = '\n'; break;
        case 'r': c = '\r'; break;
        case 't': c = '\t'; break;
        case 'v': c = '\v'; break;

        case '0': case '1': case '2': case '3':
        case '4': case '5': case '6': case '7':
        c -= '0';
        while (i++ < 2 && isdigit(*p) && *p != '8' && *p != '9')
          c = c * 8 + *p++ - '0';
        break;

        case 'x':
        c = 0;
        while (i++ < 2 && isxdigit(*p))
          {
          c = c * 16 + tolower(*p) - ((isdigit(*p))? '0' : 'W');
          p++;
          }
        break;

        case 0:   /* Allows for an empty line */
        p--;
        continue;

        case 'A':  /* Option setting */
        options |= PCRE_ANCHORED;
        continue;

        case 'B':
        options |= PCRE_NOTBOL;
        continue;

        case 'E':
        options |= PCRE_DOLLAR_ENDONLY;
        continue;

        case 'I':
        options |= PCRE_CASELESS;
        continue;

        case 'M':
        options |= PCRE_MULTILINE;
        continue;

        case 'S':
        options |= PCRE_DOTALL;
        continue;

        case 'O':
        while(isdigit(*p)) n = n * 10 + *p++ - '0';
        if (n <= (int)(sizeof(offsets)/sizeof(int))) size_offsets = n;
        continue;

        case 'Z':
        options |= PCRE_NOTEOL;
        continue;
        }
      *q++ = c;
      }
    *q = 0;
    len = q - dbuffer;

    /* Handle matching via the POSIX interface, which does not
    support timing. */

    if (posix || do_posix)
      {
      int rc;
      int eflags = 0;
      regmatch_t pmatch[30];
      if ((options & PCRE_NOTBOL) != 0) eflags |= REG_NOTBOL;
      if ((options & PCRE_NOTEOL) != 0) eflags |= REG_NOTEOL;

      rc = regexec(&preg, (char *)dbuffer, sizeof(pmatch)/sizeof(regmatch_t),
        pmatch, eflags);

      if (rc != 0)
        {
        (void)regerror(rc, &preg, (char *)buffer, sizeof(buffer));
        fprintf(outfile, "No match: POSIX code %d: %s\n", rc, buffer);
        }
      else
        {
        size_t i;
        for (i = 0; i < sizeof(pmatch)/sizeof(regmatch_t); i++)
          {
          if (pmatch[i].rm_so >= 0)
            {
            fprintf(outfile, "%2d: ", i);
            pchars(dbuffer + pmatch[i].rm_so,
              pmatch[i].rm_eo - pmatch[i].rm_so);
            fprintf(outfile, "\n");
            }
          }
        }
      }

    /* Handle matching via the native interface */

    else
      {
      if (timeit)
        {
        register int i;
        clock_t time_taken;
        clock_t start_time = clock();
        for (i = 0; i < 4000; i++)
          count = pcre_exec(re, extra, (char *)dbuffer, len, options, offsets,
            size_offsets);
        time_taken = clock() - start_time;
        fprintf(outfile, "Execute time %.2f milliseconds\n",
          ((double)time_taken)/(4 * CLOCKS_PER_SEC));
        }

      count = pcre_exec(re, extra, (char *)dbuffer, len, options, offsets,
        size_offsets);

      if (count == 0)
        {
        fprintf(outfile, "Matched, but too many substrings\n");
        count = size_offsets/2;
        }

      if (count >= 0)
        {
        int i;
        count *= 2;
        for (i = 0; i < count; i += 2)
          {
          if (offsets[i] < 0)
            fprintf(outfile, "%2d: <unset>\n", i/2);
          else
            {
            fprintf(outfile, "%2d: ", i/2);
            pchars(dbuffer + offsets[i], offsets[i+1] - offsets[i]);
            fprintf(outfile, "\n");
            }
          }
        }
      else
        {
        if (count == -1) fprintf(outfile, "No match\n");
          else fprintf(outfile, "Error %d\n", count);
        }
      }
    }

  CONTINUE:
  if (posix || do_posix) regfree(&preg);
  if (re != NULL) free(re);
  if (extra != NULL) free(extra);
  }

fprintf(outfile, "\n");
return 0;
}

/* End */
