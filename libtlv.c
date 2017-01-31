#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "libtlv.h"

/**
 * 4BVARL uses simple 7-bit VARQ encoding of 28-bit data
 * where bit7 means more data following (28-bit = 4-byte)
 * to avoid 0xff as padding, 0x80 byte can be prepended
 *
 *       DIG | HEX       | SHORTEST    | AVOID FF    |
 * ----------|-----------|-------------|-------------|
 *         0 | 0x0000000 | 00          | 00          |
 *       127 | 0x000007F | 7F          | 7F          |
 *       128 | 0x0000100 | 81 00       | 81 00       |
 *     16255 | 0x0003F7F | FE 7F       | FE 7F       |
 *     16256 | 0x0003F80 | FF 00       | 80 FF 00    |
 *     16383 | 0x0003FFF | FF 7F       | 80 FF 7F    |
 *     16384 | 0x0004000 | 81 80 00    | 81 80 00    |
 *   2080767 | 0x01FBFFF | FE 7F 7F    | FE 7F 7F    |
 *   2080768 | 0x01FC000 | FF 80 80    | 80 FF 80 80 |
 *   2097151 | 0x01FFFFF | FF FF 7F    | 80 FF FF 7F |
 *   2097152 | 0x0200000 | 81 80 80 00 | 81 80 80 00 |
 * 266338303 | 0xFDFFFFF | FE FF FF 7F | FE FF FF 7F |
 * 266338304 | 0xFE00000 | FF 80 80 00 |             |
 * 268435455 | 0xFFFFFFF | FF FF FF 7F |             |
 */

/**
 * LIBTLV_OPT_TSZMAX - get max value of type from opt
 *
 * Encoding     | No padding | FF padding
 * -------------|------------|-----------
 *  1 byte      |       0xFF |       0xFE
 *  2 bytes     |     0xFFFF |     0xFEFF
 *  4 var byets |  0xFFFFFFF |  0xFDFFFFF
 *
 * @opt:        LIBTLV_OPT_...
 * Return:      max value allowed for type
 */
static inline unsigned int LIBTLV_OPT_TSZMAX(unsigned int opt)
{
    unsigned int ret;

    switch (opt & LIBTLV_OPT_TSZMASK)
    {
        case 0:
#if     ENABLE_LIBTLV_PADDING_SUPPORT
            if (opt & LIBTLV_OPT_PADDING)
                ret = 0xFE;
            else
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/
                ret = 0xFF;
            break;
        case LIBTLV_OPT_T2BYTES:
#if     ENABLE_LIBTLV_PADDING_SUPPORT
            if (opt & LIBTLV_OPT_PADDING)
                ret = 0xFEFF;
            else
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/
                ret = 0xFFFF;
            break;
#if     ENABLE_LIBTLV_VARLEN_SUPPORT
        case LIBTLV_OPT_T4BVARL:
#if     ENABLE_LIBTLV_PADDING_SUPPORT
            if (opt & LIBTLV_OPT_PADDING)
                ret = 0xFDFFFFF;
            else
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/
                ret = 0xFFFFFFF;
            break;
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/
        default:
            ret = 0;
            break;
    }

    return ret;
}

/**
 * LIBTLV_OPT_LZMAX - get max value of length from opt
 *
 * Encoding     | No padding | FF padding
 * -------------|------------|-----------
 *  1 byte      |       0xFF |       0xFF
 *  2 bytes     |     0xFFFF |     0xFFFF
 *  4 var byets |  0xFFFFFFF |  0xFFFFFFF
 *
 * @opt:        LIBTLV_OPT_...
 * Return:      max value allowed for type
 */
static inline unsigned int LIBTLV_OPT_LSZMAX(unsigned int opt)
{
    unsigned int ret;

    switch (opt & LIBTLV_OPT_LSZMASK)
    {
        case 0:
            ret = 0xFF;
            break;
        case LIBTLV_OPT_L2BYTES:
            ret = 0xFFFF;
            break;
#if     ENABLE_LIBTLV_VARLEN_SUPPORT
        case LIBTLV_OPT_L4BVARL:
            ret = (1U << 28) - 1;
            break;
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/
        default:
            ret = 0;
            break;
    }

    return ret;
}

/**
 * LIBTLV_OPT_GETTTLVSZ - get t,l,v size from opt, t, l
 *
 * @opt:        LIBTLV_OPT_...
 * @t:          type value
 * @l:          length value
 * @tsz:        [OUT] type encoded size
 * @lsz:        [OUT] length encoded size
 * Return:      encoded size for t,l,v
 */
static inline unsigned int LIBTLV_OPT_GETTLVSZ(unsigned int opt, unsigned int t, unsigned int l,
                                               unsigned int *tsz, unsigned int *lsz)
{
    unsigned int ret = l;
    unsigned int len;

    switch (opt & LIBTLV_OPT_TSZMASK)
    {
        case 0:
            len = 1;
            break;
        case LIBTLV_OPT_T2BYTES:
            len = 2;
            break;
#if     ENABLE_LIBTLV_VARLEN_SUPPORT
        case LIBTLV_OPT_T4BVARL:
#if     ENABLE_LIBTLV_PADDING_SUPPORT
            if (opt & LIBTLV_OPT_PADDING)   /* avoid 0x7F|0x80  */
            {
                if (t < (1U << 7))          /*  7 bits:      7F */
                    len = 1;
                else if (t < 0x3F80U)       /* 14 bits:    3FFF */
                    len = 2;
                else if (t < 0x1FC000U)     /* 21 bits:  1FFFFF */
                    len = 3;
                else /* < 0xFE00000U */     /* 28 bits: FFFFFFF */
                    len = 4;
            }
            else /* no padding */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/
            {
                if (t < (1U << 7))          /*  7 bits:      7F */
                    len = 1;
                else if (t < (1U << 14))    /* 14 bits:    3FFF */
                    len = 2;
                else if (t < (1U << 21))    /* 21 bits:  1FFFFF */
                    len = 3;
                else /* < 0x10000000 */     /* 28 bits: FFFFFFF */
                    len = 4;
            }
            break;
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/
        default:
            len = 0;
            break;
    }
    if (tsz)
    {
        *tsz = len;
    }
    ret += len;

    switch (opt & LIBTLV_OPT_LSZMASK)
    {
        case 0:
            len = 1;
            break;
        case LIBTLV_OPT_L2BYTES:
            len = 2;
            break;
#if     ENABLE_LIBTLV_VARLEN_SUPPORT
        case LIBTLV_OPT_L4BVARL:
            if (l < (1U << 7))          /*  7 bits:      7F */
                len = 1;
            else if (l < (1U << 14))    /* 14 bits:    3FFF */
                len = 2;
            else if (l < (1U << 21))    /* 21 bits:  1FFFFF */
                len = 3;
            else /* < 0x10000000 */     /* 28 bits: FFFFFFF */
                len = 4;
            break;
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/
        default:
            len = 0;
            break;
    }
    if (lsz)
    {
        *lsz = len;
    }
    ret += len;

    return ret;
}

/**
 * LIBTLV_OPT_GETALIGN - get alignment bytes from from opt, tsz, lsz, ptr
 *
 * @opt:        LIBTLV_OPT_...
 * @tsz:        type encoded size
 * @lsz:        length encoded size
 * @ptr:        start position
 * Return:      number of bytes for alignment
 */
static inline unsigned int LIBTLV_OPT_GETALIGN(unsigned int opt, unsigned int tsz, unsigned int lsz, uintptr_t ptr)
{
#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    unsigned int ret = 0;
    unsigned int mask;

    mask = (opt & LIBTLV_OPT_ALNCNT) >> (__builtin_ffs(LIBTLV_OPT_ALNCNT)-1);
    if (mask == 0)
    {
        return 0;
    }
    mask = (1U << mask) - 1;

    switch (opt & LIBTLV_OPT_ALNSEL)
    {
        case LIBTLV_OPT_ALIGNT:
            break;
        case LIBTLV_OPT_ALIGNL:
            ptr += tsz;
            break;
        case LIBTLV_OPT_ALIGNV:
            ptr += tsz + lsz;
            break;
        default:
            return 0;
    }
    if (ptr & mask)
    {
        ret = (~ptr & mask) + 1;
    }

    return ret;
#else  /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    return 0;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/
}

/**
 * LIBTLV_OPT_GETTYPE - get next type assuming size > 0
 * padding can be skipped here
 */
#if     ENABLE_LIBTLV_PADDING_SUPPORT
#define LIBTLV_OPT_GETTYPE_PADDING(_opt, _type, _ptr, _size, _nul, _end, _err) \
    if (_opt & LIBTLV_OPT_PADDING)                                             \
    {                                                                          \
        while (*(uint8_t*)_ptr == 0xFF)                                        \
        {                                                                      \
            ++_ptr;                                                            \
            if (--_size == 0)                                                  \
                _end;                                                          \
        }                                                                      \
    }
#else /*ENABLE_LIBTLV_PADDING_SUPPORT*/
#define LIBTLV_OPT_GETTYPE_PADDING(_opt, _type, _ptr, _size, _nul, _end, _err)
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

#if     ENABLE_LIBTLV_VARLEN_SUPPORT
#define LIBTLV_OPT_GETTYPE_VARLEN(_opt, _type, _ptr, _size, _nul, _end, _err)  \
        case LIBTLV_OPT_T4BVARL:                                               \
            /* byte 0 cannot be zero */                                        \
            if ((_type = *(uint8_t*)_ptr))                                     \
            {                                                                  \
                _type &= 0x7FU;                                                \
                ++_ptr;                                                        \
                --_size;                                                       \
            }                                                                  \
            else /* at end */                                                  \
                _nul;                                                          \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) == 0)                           \
                break;                                                         \
            /* byte 1 */                                                       \
            if (_size == 0)                                                    \
                _err;                                                          \
            _type <<= 7;                                                       \
            _type |= *(uint8_t*)_ptr++ & 0x7FU; --_size;                       \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) == 0)                           \
                break;                                                         \
            /* byte 2 */                                                       \
            if (_size == 0)                                                    \
                _err;                                                          \
            _type <<= 7;                                                       \
            _type |= *(uint8_t*)_ptr++ & 0x7FU; --_size;                       \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) == 0)                           \
                break;                                                         \
            /* byte 3 */                                                       \
            if (_size == 0)                                                    \
                _err;                                                          \
            _type <<= 7;                                                       \
            _type |= *(uint8_t*)_ptr++ & 0x7FU; --_size;                       \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) != 0)                           \
                _err;                                                          \
            break;
#else /*ENABLE_LIBTLV_VARLEN_SUPPORT*/
#define LIBTLV_OPT_GETTYPE_VARLEN(_opt, _type, _ptr, _size, _nul, _end, _err)
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/

#define LIBTLV_OPT_GETTYPE(_opt, _type, _ptr, _size, _nul, _end, _err)         \
    LIBTLV_OPT_GETTYPE_PADDING(_opt, _type, _ptr, _size, _nul, _end, _err)     \
    switch (_opt & LIBTLV_OPT_TSZMASK)                                         \
    {                                                                          \
        case 0:                                                                \
            if ((_type = *(uint8_t*)_ptr))                                     \
            {                                                                  \
                ++_ptr;                                                        \
                --_size;                                                       \
            }                                                                  \
            else /* at end */                                                  \
                _nul;                                                          \
            break;                                                             \
        case LIBTLV_OPT_T2BYTES:                                               \
            if (_size < 2)                                                     \
                _err;                                                          \
            if ((_type = (((((uint16_t)(((uint8_t*)_ptr)[0]))) << 8) |         \
                          ((uint8_t*)_ptr)[1])))                               \
            {                                                                  \
                _ptr  += 2;                                                    \
                _size -= 2;                                                    \
            }                                                                  \
            else /* at end */                                                  \
                _nul;                                                          \
            break;                                                             \
        LIBTLV_OPT_GETTYPE_VARLEN(_opt, _type, _ptr, _size, _nul, _end, _err)  \
    }                                                                          \

/**
 * LIBTLV_OPT_GETLENGTH - get next length assuming size > 0
 */
#if     ENABLE_LIBTLV_VARLEN_SUPPORT
#define LIBTLV_OPT_GETLENGTH_VARLENG(_opt, _length, _ptr, _size, _err)         \
        case LIBTLV_OPT_L4BVARL:                                               \
            /* byte 0 */                                                       \
            _length = *(uint8_t*)_ptr++ & 0x7FU; --_size;                      \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) == 0)                           \
                break;                                                         \
            /* byte 1 */                                                       \
            if (_size == 0)                                                    \
                _err;                                                          \
            _length <<= 7;                                                     \
            _length |= *(uint8_t*)_ptr++ & 0x7FU; --_size;                     \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) == 0)                           \
                break;                                                         \
            /* byte 2 */                                                       \
            if (_size == 0)                                                    \
                _err;                                                          \
            _length <<= 7;                                                     \
            _length |= *(uint8_t*)_ptr++ & 0x7FU; --_size;                     \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) == 0)                           \
                break;                                                         \
            /* byte 3 */                                                       \
            if (_size == 0)                                                    \
                _err;                                                          \
            _length <<= 7;                                                     \
            _length |= *(uint8_t*)_ptr++ & 0x7FU; --_size;                     \
            if ((((uint8_t*)_ptr)[-1] & 0x80U) != 0)                           \
                _err;                                                          \
            break;
#else /*ENABLE_LIBTLV_VARLEN_SUPPORT*/
#define LIBTLV_OPT_GETLENGTH_VARLENG(_opt, _length, _ptr, _size, _err)
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/

#define LIBTLV_OPT_GETLENGTH(_opt, _length, _ptr, _size, _err)                 \
    switch (_opt & LIBTLV_OPT_LSZMASK)                                         \
    {                                                                          \
        case 0:                                                                \
            _length = *(uint8_t*)_ptr++;                                       \
            --_size;                                                           \
            break;                                                             \
        case LIBTLV_OPT_L2BYTES:                                               \
            if (_size < 2)                                                     \
                _err;                                                          \
            _length = (((((uint16_t)((uint8_t*)_ptr)[0])) << 8) |              \
                       ((uint8_t*)_ptr)[1]);                                   \
            _ptr  += 2;                                                        \
            _size -= 2;                                                        \
            break;                                                             \
        LIBTLV_OPT_GETLENGTH_VARLENG(_opt, _length, _ptr, _size, _err)         \
    }                                                                          \

/**
 * libtlv_get - get tlv
 *
 * caller needs to check *t to see if it matches
 * tvl ends with single 0 (no length/value)
 *
 * @opt:        options
 * @buf:        tlv buffer
 * @size:       buffer size
 * @t:          [INOUT] null to find end, ->0 to find next, or ->type to match
 * @l:          [INOUT] null to ignore length, ->0 for get ptr in v, otherwise->max of v, return actual length
 * @v:          [OUT] null to ignore value, ptr to value if l->0, otherwise copy value (max *l)
 * Return:      negative error or offset at end or after found tlv
 */
int libtlv_get(unsigned int opt, void *buf, size_t size, unsigned int *t, unsigned int *l, void *v)
{
    int ret = size;
    int found = 0;
    unsigned int max = (l ? *l : 0);

    if (ret < 0)
    {
        return -E2BIG;
    }
    if (buf == NULL && size > 0)
    {
        return -EINVAL;
    }
    if (t && *t > LIBTLV_OPT_TSZMAX(opt))
    {
        return -EINVAL;
    }
    if ((t == NULL) && (l != NULL || v != NULL))
    {
        return -EINVAL;
    }
    if ((l == NULL) && (v != NULL))
    {
        return -EINVAL;
    }

    while (size > 0)
    {
        void *ptr = buf;
        unsigned int type, length;

        LIBTLV_OPT_GETTYPE(opt, type, ptr, size, goto out, goto out, return -EFAULT)
        if (size == 0)
        {
            return -EFAULT;
        }
        LIBTLV_OPT_GETLENGTH(opt, length, ptr, size, return -EFAULT)
        if (size < length)
        {
            return -EFAULT;
        }
        size -= length;
        buf = ptr + length;

        if (t == NULL) /* seek eof */
        {
            continue;
        }
        if (*t == 0 || *t == type)
        {
            if (*t == 0)
            {
                *t = type; /* next */
            }
            if (l)
            {
                *l = length;
                if (v)
                {
                    if (max == 0)
                    {
                        if (length == 0)
                            ptr = NULL;
                        if (((unsigned long)v) & (__alignof__(void*)-1))
                            memcpy(v, &ptr, sizeof(void*));
                        else
                            *(void**)v = ptr;
                    }
                    else if (length)
                    {
                        memcpy(v, ptr, length > max ? max : length);
                    }
                }
            }
            if (opt & LIBTLV_OPT_GET_LAST)
            {
                found = 1;
                continue;
            }
            return ret - size;
        }
    }

out:
    if (!found && t)
    {
        *t = 0;
    }
    return ret - size;
}

/**
 * libtlv_put - put tlv
 *
 * @opt:        options
 * @buf:        tlv buffer
 * @size:       buffer size
 * @t:          type
 * @l:          length
 * @v:          value
 * Return:      negative error or offset at end or after put tlv
 */
int libtlv_put(unsigned int opt, void *buf, size_t size, unsigned int t, unsigned int l, void *v)
{
    int ret = size;

    if (ret < 0)
    {
        return -E2BIG;
    }
    if (buf == NULL && size > 0)
    {
        return -EINVAL;
    }
    if (t > LIBTLV_OPT_TSZMAX(opt) || l > LIBTLV_OPT_LSZMAX(opt))
    {
        return -EINVAL;
    }
    if (t && l && !v)
    {
        return -EINVAL;
    }

    while (size > 0)
    {
        void *ptr = buf;
        unsigned int type, length;

        LIBTLV_OPT_GETTYPE(opt, type, ptr, size, break, return -ENOSPC, return -EFAULT)
        if (size == 0)
        {
            return -EFAULT;
        }
        if (type == 0)
        {
            if (t)
            {
#if     ENABLE_LIBTLV_ALIGN_SUPPORT
                unsigned int pad, tsz, lsz;
                unsigned int sz = LIBTLV_OPT_GETTLVSZ(opt, t, l, &tsz, &lsz);
                if (size < sz)
                    return -ENOSPC;
                pad = LIBTLV_OPT_GETALIGN(opt, tsz, lsz, (uintptr_t)ptr);
                if (pad > 0)
                {
                    if (size < pad+sz)
                        return -ENOSPC;
                    memset(ptr, 0xff, pad);
                    ptr += pad;
                    sz += pad;
                }
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
                unsigned int sz = LIBTLV_OPT_GETTLVSZ(opt, t, l, NULL, NULL);
                if (size < sz)
                    return -ENOSPC;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/
                /* put type */
                switch (opt & LIBTLV_OPT_TSZMASK)
                {
                    case 0:
                        *(uint8_t*)(ptr++) = t;
                        break;
                    case LIBTLV_OPT_T2BYTES:
                        *(uint8_t*)(ptr++) = (t >> 8);
                        *(uint8_t*)(ptr++) = (t & 0xFF);
                        break;
                    case LIBTLV_OPT_T4BVARL:
                        if (t < (1U << 7))
                        {
                            *(uint8_t*)(ptr++) = t;
                        }
                        else if (t < (1U << 14))
                        {
                            *(uint8_t*)(ptr++) = ((t >>  7) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = (t & 0x7F);
                        }
                        else if (t < (1U << 21))
                        {
                            *(uint8_t*)(ptr++) = ((t >> 14) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = ((t >>  7) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = (t & 0x7F);
                        }
                        else
                        {
                            *(uint8_t*)(ptr++) = ((t >> 21) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = ((t >> 14) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = ((t >>  7) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = (t & 0x7F);
                        }
                        break;
                }
                /* put length */
                switch (opt & LIBTLV_OPT_LSZMASK)
                {
                    case 0:
                        *(uint8_t*)(ptr++) = l;
                        break;
                    case LIBTLV_OPT_L2BYTES:
                        *(uint8_t*)(ptr++) = (l >> 8);
                        *(uint8_t*)(ptr++) = (l & 0xFF);
                        break;
                    case LIBTLV_OPT_L4BVARL:
                        if (l < (1U << 7))
                        {
                            *(uint8_t*)(ptr++) = l;
                        }
                        else if (l < (1U << 14))
                        {
                            *(uint8_t*)(ptr++) = ((l >>  7) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = (l & 0x7F);
                        }
                        else if (l < (1U << 21))
                        {
                            *(uint8_t*)(ptr++) = ((l >> 14) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = ((l >>  7) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = (l & 0x7F);
                        }
                        else
                        {
                            *(uint8_t*)(ptr++) = ((l >> 21) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = ((l >> 14) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = ((l >>  7) & 0x7F) | 0x80;
                            *(uint8_t*)(ptr++) = (l & 0x7F);
                        }
                        break;
                }
                if (l) memcpy(ptr, v, l);
                size -= sz;
            }
            return ret - size;
        }
        LIBTLV_OPT_GETLENGTH(opt, length, ptr, size, return -EFAULT)
        if (size < length)
        {
            return -EFAULT;
        }
        size -= length;
        buf = ptr + length;

        if ((type == t) && (opt & LIBTLV_OPT_PUT_ONCE))
        {
            return -EEXIST;
        }
    }
    return -ENOSPC;
}

/*
 * Local Variables:
 *   c-file-style: "stroustrup"
 *   indent-tabs-mode: nil
 * End:
 *
 * vim: set ai cindent et sta sw=4:
 */
