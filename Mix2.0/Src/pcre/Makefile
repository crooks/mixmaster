# Make file for PCRE (Perl-Compatible Regular Expression) library.

# Edit CC, CFLAGS, and RANLIB for your system.

# It is believed that RANLIB=ranlib is required for AIX, BSDI, FreeBSD, Linux,
# MIPS RISCOS, NetBSD, OpenBSD, Digital Unix, and Ultrix.

# Use CFLAGS = -DUSE_BCOPY on SunOS4 and any other system that lacks the
# memmove() function, but has bcopy().

# Use CFLAGS = -DSTRERROR_FROM_ERRLIST on SunOS4 and any other system that
# lacks the strerror() function, but can provide the equivalent by indexing
# into errlist.

CC = gcc
CFLAGS = -O2 -Wall
RANLIB = ranlib

##########################################################################

OBJ = chartables.o study.o pcre.o

all:            libpcre.a libpcreposix.a pcretest pgrep

pgrep:          libpcre.a pgrep.o
		$(CC) $(CFLAGS) -o pgrep pgrep.o libpcre.a

pcretest:       libpcre.a libpcreposix.a pcretest.o
		$(CC) $(CFLAGS) -o pcretest pcretest.o libpcre.a libpcreposix.a

libpcre.a:      $(OBJ)
		rm -f libpcre.a
		ar cq libpcre.a $(OBJ)
		$(RANLIB) libpcre.a

libpcreposix.a: pcreposix.o
		rm -f libpcreposix.a
		ar cq libpcreposix.a pcreposix.o
		$(RANLIB) libpcreposix.a

pcre.o:         pcre.c pcre.h internal.h Makefile
		$(CC) -c $(CFLAGS) pcre.c

pcreposix.o:    pcreposix.c pcreposix.h internal.h Makefile
		$(CC) -c $(CFLAGS) pcreposix.c

chartables.o:   chartables.c
		$(CC) -c $(CFLAGS) chartables.c

study.o:        study.c pcre.h internal.h Makefile
		$(CC) -c $(CFLAGS) study.c

pcretest.o:     pcretest.c pcre.h Makefile
		$(CC) -c $(CFLAGS) pcretest.c

pgrep.o:        pgrep.c pcre.h Makefile
		$(CC) -c $(CFLAGS) pgrep.c

# An auxiliary program makes the character tables

chartables.c:    maketables
		./maketables >chartables.c

maketables:     maketables.c Makefile
		$(CC) -o maketables $(CFLAGS) maketables.c

# We deliberately omit maketables and chartables.c from 'make clean'; once made
# chartables.c shouldn't change, and if people have edited the tables by hand,
# you don't want to throw them away.

clean:;         /bin/rm -f *.o *.a pcretest pgrep

# Run the tests

runtest:        all
		./pcretest testinput testtry
		diff testtry testoutput
		./pcretest -i testinput2 testtry
		diff testtry testoutput2
		rm -f testtry

# End
