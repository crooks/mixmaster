
/* $Id: sockio.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: sockio.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.2  1998/04/13  23:22:29  um
 * re-indented.
 *
 *
 * sockio.c           1997-11-08 um
 *     new funtions.
 *
 * sockio.c           1997-09-11 um
 */

#include "mix.h"
#include "inet.h"
#include <stdlib.h>
#include <errno.h>

#define MAXLINE 512

/* The following I/O procedures are from Network programming */

/*
 * Write "n" bytes to a descriptor.
 * Use in place of write() when fd is a stream socket.
 */

int
writen (int fd, char *ptr, int nbytes)
{
  int nleft, nwritten;

  nleft = nbytes;
  while (nleft > 0)
    {
      nwritten = write (fd, ptr, nleft);
      if (nwritten <= 0)
	return (nwritten);	/* error */

      nleft -= nwritten;
      ptr += nwritten;
    }
  return (nbytes - nleft);
}

/*
 * Read "n" bytes from a descriptor.
 * Use in place of read() when fd is a stream socket.
 */

int
readn (int fd, char *ptr, int nbytes)
{
  int nleft, nread;

  nleft = nbytes;
  while (nleft > 0)
    {
      nread = read (fd, ptr, nleft);
      if (nread < 0)
	return (nread);		/* error, return < 0 */
      else if (nread == 0)
	break;			/* EOF */

      nleft -= nread;
      ptr += nread;
    }
  return (nbytes - nleft);	/* return >= 0 */
}


/*
 * Read a line from a descriptor. Read the line one byte at a time,
 * looking for the newline. We store the newline in the buffer,
 * then follow it with a null (the same as fgets(3)).
 * We return the number of characters up to, but not including,
 * the null (the same as strlen(3)).
 */

int
readline (register int fd,
	  register char *ptr,
	  register int maxlen)
{
  int n, rc;
  char c;

  *ptr = 0;
  for (n = 1; n < maxlen; n++)
    {
      if ((rc = read (fd, &c, 1)) == 1)
	{
	  *ptr++ = c;
	  if (c == '\n')
	    break;
	}
      else if (rc == 0)
	{
	  if (n == 1)
	    return (0);		/* EOF, no data read */
	  else
	    break;		/* EOF, some date read */
	}
      else
	return (-1);		/* error */
    }
  *ptr = 0;
  return (n);
}

/* returns 1 on success */
int
writestr (int fd, char *s)
{
  return (writen (fd, s, strlen (s)) == strlen (s));
}

int
writebuf (int fd, BUFFER * b)
{
  int len, n;
  len = htons (b->length);
  writen (fd, (char *) &len, sizeof (len));
  n = writen (fd, b->message, b->length);
  return (n == b->length);
}

int
readbuf (int fd, BUFFER * b)
{
  int len;
  char *p;

  if (readn (fd, (char *) &len, sizeof (len)) != sizeof (len))
    return (0);
  len = ntohs (len);
  if (len > 32 * 1024)
    return (0);
  p = malloc (len);
  if (readn (fd, p, len) != len)
    return (0);
  add_to_buffer (b, p, len);
  free (p);
  return (1);
}
