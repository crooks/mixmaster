OBJS = bsafeeay.o
SRC = bsafeeay.c
INCLUDE = -I. -I../ssleay/include -I../ssleay/include/openssl
CC = gcc
CFLAGS = -ggdb
AR = ar
RANLIB = ranlib

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

libbsafe.a: $(OBJS)
	$(AR) rc libbsafe.a $(OBJS)
	$(RANLIB) libbsafe.a

clean:
	rm -f *.o libbsafe.a
