# Use the internal EATSPAM mechanism.
# Add a Message-ID.

MID="<`md5sum | sed 's/\([0-9a-f]*\).*/\1@'$HOSTNAME'/'`>"

:0 fh
| formail -bf "-aMessage-ID: $MID"

# Check against the cache.

DUMMY=`lockfile ${CACHE}${LOCKEXT}`

:0 
* ? formail -D $CACHESIZE $CACHE
{
        TRAP="rm -f ${CACHE}${LOCKEXT}"

	:0 :
	| formail "-aDate: $DATE" >>$DUPLICATES
}

DUMMY=`rm -f ${CACHE}${LOCKEXT}` # avoid deadlock if remixing
