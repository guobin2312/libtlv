# libtlv

Simple tlv library supporting variable length encoding, padding, alignment and
etc.

Read (get) and write (put) functions operate on tlv buffer (empty or not) of a
given size with 0 as end or empty, and 0xff as padding.

## Reading or get

    int libtlv_get(unsigned int opt, void *buf, size_t size, unsigned int *t, unsigned int *l, void *v);

caller needs to check `*t` to see if it matches tvl ends with single 0 (no length or value)

 * `opt`:        options
 * `buf`:        tlv buffer
 * `size`:       buffer size
 * `t`:          [INOUT] null to find end, -> 0 to find next, or -> type to match
 * `l`:          [INOUT] null to ignore length, -> 0 for get ptr in v, otherwise -> max of v, return actual length
 * `v`:          [OUT] null to ignore value, ptr to value if l -> 0, otherwise copy value (max `*l`)
 * Return:       negative error or offset at end or after found tlv

Note this function can be used to

 * find particular type `t`, copy value into `v` (no more than `*l`) and return actual length into `l`
 * find last tlv entry matching `t`
 * find end of tlv (zero or end of buffer)
 * return pointer to value into `v`
 * get next tlv entry for looping

## Writing or put

    int libtlv_put(unsigned int opt, void *buf, size_t size, unsigned int  t, unsigned int  l, void *v);

 * `opt`:        options
 * `buf`:        tlv buffer
 * `size`:       buffer size
 * `t`:          type
 * `l`:          length
 * `v`:          value
 * Return:       negative error or offset at end or after put tlv

Note this function can be used to

 * skip existing tlv and put at the end
 * optionally return failure if type `t` already in buffer

## Encoding

Both `t` and `l` are encoded in network order (big-endian) of 1 or 2 bytes in fixed encoding:

 * 1 byte:       max 0xFF
 * 2 bytes:      max 0xFFFF

For variable sized `t` and `l`, maximum 4-bytes of 7-bit encoding is used as as in [VLQ](https://en.wikipedia.org/wiki/Variable-length_quantity).

 * 1 byte:       max 0x7F
 * 2 bytes:      max 0x3FFF
 * 3 bytes:      max 0x1FFFFF
 * 4 bytes:      max 0xFFFFFFF

## Padding and alignment

Choosing 0xFF as padding makes alignment (of t, l or v) possible, but limit range of t:

 * 1 byte:       max 0xFE
 * 2 bytes:      max 0xFEFF
 * var 4 bytes:  max 0xFDFFFFF

Note for variable encoding, to avoid 0xFF, some values start with 0x80.

## Recursive tlv

When outputing recursive tlv, space of t and l can be reserved (initialized to zero) and fill up later:

    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, size, t, 0, NULL); /* space of t,l set to 0 */
    l = fill_sub_tlv(buf + ret, size-ret, ...);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, size, t, l, NULL); /* space of t,l filled up */
