
/* $Id: random.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: random.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.5  1998/04/15  23:10:02  um
 * gcc warning removed.
 *
 * Revision 2.4  1998/04/13  23:22:29  um
 * patch for reading randomness from keyboard on DOS.
 *
 * Revision 2.3  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 *
 * Revision 2.2  1998/01/12  21:45:49  um
 * OpenBSD /dev/random patch (Richard Johnson)
 *
 * random.c            1997-06-09 um
 *      several corrections and improvements. Support for NOISE.SYS (MSDOS)
 *
 * random.c        1.1 1996-09-17 um
 *      added spport for /dev/random (not yet for MSDOS)
 *
 * random.c        1.0 4/23/95
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
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <assert.h>

#ifdef MSDOS
#include <pc.h>
#define DEV_URANDOM "/dev/urandom$"
#define DEV_RANDOM "/dev/random$"
#ifndef O_NDELAY
#define O_NDELAY 0
#endif
#else
#define DEV_URANDOM "/dev/urandom"
#ifdef __OpenBSD__
#define DEV_RANDOM "/dev/srandom"
#else
#define DEV_RANDOM "/dev/random"
#endif
#endif

#define BYTES_NEEDED 128

static int initialized = 0;

RANDOM random_obj;

void
init_our_random (void)
{
  FILE *fp, *lockptr;
  byte privseed[256];
  int seeded = 0;

#ifdef USE_RSAREF
  if (R_RandomInit (&random_obj) == 0)
    initialized = 1;
#else
  if (B_CreateAlgorithmObject (&random_obj) != 0)
    return;
  if (B_SetAlgorithmInfo (random_obj, AI_MD5Random, 0) != 0)
    return;
  if (B_RandomInit (random_obj, CHOOSER, NULL) != 0)
    return;
  initialized = 1;
#endif
  /* Setup random number seeding */

  mix_lock ("mixrand", &lockptr);
  if ((fp = try_open_mix_file (MIXRAND, "rb")) != NULL)
    {
      if (fread (privseed, sizeof (privseed), 1, fp) > 0)
	seeded = 1;
      fclose (fp);
    }
  if (!seeded)
    get_randomness ();
  mix_unlock ("mixrand", lockptr);
  add_to_random (privseed, sizeof (privseed));
  memset (privseed, 0, sizeof (privseed));
  get_noise ();
}

void
close_our_random (void)
{
  FILE *fp, *lockptr;
  byte privseed[256];

  if (!initialized)
    return;
  our_randombytes (privseed, sizeof (privseed));
  mix_lock ("mixrand", &lockptr);
  if ((fp = open_mix_file (MIXRAND, "wb")) != NULL)
    {
      fwrite (privseed, sizeof (privseed), 1, fp);
      fclose (fp);
    }
  mix_unlock ("mixrand", lockptr);
  memset (privseed, 0, sizeof (privseed));
#ifdef USE_RSAREF
  R_RandomFinal (&random_obj);
#else
  B_DestroyAlgorithmObject (&random_obj);
#endif

  initialized = 0;
}

byte *
our_randombytes (byte * b, int n)
{
  assert (initialized == 1);
#ifdef USE_RSAREF
  while (R_GenerateBytes (b, n, &random_obj) == RE_NEED_RANDOM)
    get_noise ();
#else
  while (B_GenerateRandomBytes (random_obj, b, n, NULL) != 0)
    get_noise ();
#endif
  return b;
}

byte
our_randombyte (void)
{
  byte foo;

  our_randombytes (&foo, 1);
  return (foo);
}

int
random_number (int n)
{
  int r;
  assert (n > 0);
  if (n > 255)
    do
      r = our_randombyte () * 65536 +
	our_randombyte () * 256 + our_randombyte ();
    while (r >= n);
  else
    do
      r = our_randombyte ();
    while (r >= n);
#ifdef DEBUG
  printf ("%d (%d)\n", r, n);
#endif
  return r;
}

void
add_to_random (unsigned char *buff, int len)
{
#ifdef USE_RSAREF
  R_RandomUpdate (&random_obj, buff, len);
#else
  B_RandomUpdate (random_obj, buff, len, NULL);
#endif
}

void
get_noise (void)
{
  int fd;
  unsigned char b[256];
#ifdef USE_RSAREF
  int needed;
#endif

  if ((fd = open (DEV_URANDOM, O_RDONLY)) != 1)
    {
      read (fd, b, sizeof (b));
      add_to_random (b, sizeof (b));
      close (fd);
    }
#ifdef USE_RSAREF
  do
    {
      rnd_time ();		/* fake randomness. :-( */
      R_GetRandomBytesNeeded (&needed, &random_obj);
    }
  while (needed > 0);
#endif
}

#define dev_random (fd != -1)
#ifdef MSDOS
#define tty_in 1
#else
#define tty_in (isatty (fileno (stdin)))
#endif

void
get_randomness (void)
{
  byte b[256], c = 0;
  int fd;
  int bytes = 0;

  fd = open (DEV_RANDOM, O_RDONLY | O_NDELAY);

  if (dev_random)
    {
      bytes = read (fd, b, sizeof (b));	/* get entropy from /dev/random */
      add_to_random (b, sizeof (b));	/* read up to 256 bytes */
      close (fd);
      fd = open (DEV_RANDOM, O_RDONLY);	/* re-open in blocking mode */
    }
  else
    {
      /* READ OTHER RANDOMNESS SOURCES HERE */
    }

  /* If that was not enough entropy, we need input from the user.
     When run in the background, we poll /dev/random if available */

  if (bytes < BYTES_NEEDED && (tty_in || dev_random))
    {
      if (tty_in)
	{
	  if (dev_random)
	    fprintf (stderr, "Please move the mouse, enter random characters, etc.\n");
	  else
	    fprintf (stderr, "Please enter some random characters.\n");
	  kbd_echo (0);
	}

      while (bytes < BYTES_NEEDED)
	{
	  if (tty_in)
	    fprintf (stderr, "  %d     \r", BYTES_NEEDED - bytes);
	  if (dev_random)
	    {
	      if (read (fd, b, 1) > 0)
		{
		  add_to_random (b, 1);
		  bytes++;
		}
	    }
	  else
	    /* get entropy from user */
	    {
#ifdef MSDOS
	      if (kbhit ())
		{
		  *b = getkey ();
#else
	      if (read (fileno (stdin), b, 1) > 0)
		{
#endif
		  add_to_random (b, 1);
		  rnd_time ();
		  if (*b != c)
		    bytes++;
		  c = *b;
		}
	    }
	}
      if (tty_in)
	{
	  fprintf (stderr, "Thanks.\n");
	  sleep (1);
	  kbd_echo (1);
	}
    }
  if (dev_random)
    close (fd);
}

int
rnd_time (void)
{
  struct timeval tv;
  static long last;
  int r;

  gettimeofday (&tv, 0);
  add_to_random ((unsigned char *) &tv, sizeof (tv));
  r = (tv.tv_usec - last > 100000);
  last = tv.tv_usec;
  return r;
}

int
kbd_echo (int on)
{
  int fd;
  struct termios attr;

  if (on)
    setvbuf (stdin, NULL, _IOLBF, BUFSIZ);
  else
    setbuf (stdin, NULL);

  fd = fileno (stdin);
  if (tcgetattr (fd, &attr) != 0)
    return -1;
  if (on)
    attr.c_lflag |= ECHO | ICANON;
  else
    attr.c_lflag &= ~(ECHO | ICANON);
  if (tcsetattr (fd, TCSAFLUSH, &attr) != 0)
    return -1;
  return 0;
}
