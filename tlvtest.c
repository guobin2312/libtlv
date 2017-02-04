#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "libtlv.h"

/* global buffers */
#define GLOBAL_LEN      2048
uint8_t global_tmp[GLOBAL_LEN] __attribute__((aligned(128)));
uint8_t global_buf[GLOBAL_LEN] __attribute__((aligned(128)));

/* error code */
#define ERROR_PUT       1
#define ERROR_GET       2
#define ERROR_CMP       3
#define ERROR_RET       4

/* error line number */
int ERROR_LINE;
/* return error with line numer */
#define RETURN_ERROR(err)       return (ERROR_LINE = __LINE__, err)

#if 0
/* strspn with n */
static int strnspn(size_t n, const char *s, const char *accept)
{
    if (s == NULL || accept == NULL)
        return -1;
    else
    {
        int i;

        for (i = 0; i < n && s[i] && strchr(accept, s[i]); ++i)
            ;
        return i;
    }
}
#endif

#if 1
/* memset check */
static int memspn(void *s, int c, size_t n)
{
    if (s == NULL)
        return -1;
    else
    {
        int i;

        for (i = 0; i < n; ++i)
        {
            if (((const uint8_t*)s)[i] != c)
                break;
        }

        return i;
    }
}
#endif

/*
 * BEGIN tll1n: t=1 l=1 no padding
 */

/* test tlv get return */
static int test_t1l1n_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L1N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFF => -EINVAL */
    t = (1<<8);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;2,1,1;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t1l1n_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L1N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,1,1;2,2,12;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[1,1,1;2,2,12;0] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,2,12] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,2,12;0] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,2,12] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,2,12;0] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[1,1,1;2,2,12] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[1,1,1;2,6,123456;0] t->2, l->4 => off-1, t==2, l==6 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,1,1;2,6,123456] t->2, l->4 => off-1, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,1,1;2,2,12;1,3,123;0] t->1 => off-1, t==1, l==3 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[1,1,1;2,2,12;1,3,123] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t1l1n_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L1N;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,1,1;2,6,123456;3,2,12;4,4,1234;5,0;0] */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 4;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 1,1,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 2,6,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 6 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4,4,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,0 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t1l1n_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L1N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFF => -EINVAL */
    t = (1<<8);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFF => -EINVAL */
    t = 1;
    l = (1<<8);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;0] t==0, l==1 => 3 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 3)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[1,1,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t1l1n_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L1N;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=1, l=1, v=1 */
    tmp[off+0] = 1;
    tmp[off+1] = 1;
    tmp[off+2] = 1;
    ret = libtlv_put(opt, buf, len, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* init+fini: t=2, l=3, v=123 */
    tmp[off+0] = 2;
    tmp[off+1] = 3;
    memcpy(&tmp[off+2], "123", 3);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, tmp[off+0], tmp[off+1], NULL);
    if (ret != 2 || buf[0] || buf[1])
        RETURN_ERROR(ERROR_PUT);
    memcpy(buf+ret, "123", tmp[off+1]);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, 2, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != 2)
        RETURN_ERROR(ERROR_PUT);
    ret += tmp[off+1];
    buf += ret;
    len -= ret;
    off += ret;

    /* t=3, l=4, v=123\0 */
    tmp[off+0] = 3;
    tmp[off+1] = 4;
    memcpy(&tmp[off+2], "123", 4);
    ret = libtlv_put(opt, buf, len, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=4, l=5, v=12345 */
    tmp[off+0] = 4;
    tmp[off+1] = 5;
    memcpy(&tmp[off+2], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != off + 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    tmp[off+0] = 4;
    tmp[off+1] = 6;
    memcpy(&tmp[off+2], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != off + 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END tll1n: t=1 l=1 no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN tll1p: t=1 l=1 with padding
 */

/* test tlv get return */
static int test_t1l1p_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L1P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFE => -EINVAL */
    t = 0xFF;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1,1;ff;2,1,1;ff;ff;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t1l1p_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L1P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,1,1;ff;2,2,12;ff;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[1,1,1;ff;2,2,12;ff;0] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,2,12;ff] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,2,12;ff;0] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,2,12;ff] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,2,12;ff;0] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[1,1,1;ff;2,2,12;ff] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[ff;1,1,1;ff;2,6,123456;0] t->2, l->4 => off-1, t==2, l==6 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[ff;1,1,1;ff;2,6,123456] t->2, l->4 => off-1, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[ff;1,1,1;ff;2,2,12;ff;1,3,123;0] t->1 => off-1, t==1, l==3 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[ff;1,1,1;ff;2,2,12;ff;1,3,123] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t1l1p_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L1P;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;1,1,1;ff;ff;2,6,123456;3,2,12;4,4,1234;5,0;ff;ff;0] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 4;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3 + l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4 + l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2 + l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2 + l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2 + l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 0xff;1,1,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 0xff;0xff;2,6,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 6 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4,4,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,0 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 0xff;0xff;0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t1l1p_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L1P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFE => -EINVAL */
    t = 0xFF;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFF => -EINVAL */
    t = 1;
    l = (1<<8);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;ff,ff,ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1,1;ff,ff,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;ff;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;ff;ff;ff;0] t==0, l==1 => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != off-1)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[ff;1,1,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t1l1p_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L1P;
    unsigned int p = 0;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align t to 2 */
    tmp[off++] = 0xff; // 1
    p = 1;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=1, l=1, v=1 */
    tmp[off+0] = 1;
    tmp[off+1] = 1;
    tmp[off+2] = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNT | LIBTLV_OPT_ALN2B,
                     buf, len, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != p + 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align t to 4 */
    tmp[off++] = 0xff; // 5
    tmp[off++] = 0xff; // 6
    tmp[off++] = 0xff; // 7
    p = 3;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* init+fini: t=2, l=3, v=123 */
    tmp[off+0] = 2;
    tmp[off+1] = 3;
    memcpy(&tmp[off+2], "123", 3);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNT | LIBTLV_OPT_ALN4B | LIBTLV_OPT_PUT_INIT,
                     buf, len, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != p + 2 || buf[p+0] || buf[p+1])
        RETURN_ERROR(ERROR_PUT);
    memcpy(buf+ret, "123", tmp[off+1]);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNT | LIBTLV_OPT_ALN4B | LIBTLV_OPT_PUT_FINI,
                     buf, len, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != p + 2)
        RETURN_ERROR(ERROR_PUT);
    ret += tmp[off+1];
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align t to 8 */
    tmp[off++] = 0xff; // 13
    tmp[off++] = 0xff; // 14
    tmp[off++] = 0xff; // 15
    p = 3;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=3, l=4, v=123\0 */
    tmp[off+0] = 3;
    tmp[off+1] = 4;
    memcpy(&tmp[off+2], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNT | LIBTLV_OPT_ALN8B,
                     buf, len, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != p + 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=4, l=5, v=12345 */
    tmp[off+0] = 4;
    tmp[off+1] = 5;
    memcpy(&tmp[off+2], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != off + 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    tmp[off+0] = 4;
    tmp[off+1] = 6;
    memcpy(&tmp[off+2], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], tmp[off+1], &tmp[off+2]);
    if (ret != off + 2 + tmp[off+1])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END tll1p: t=1 l=1 with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

/*
 * BEGIN t2l1n: t=2 l=1 no padding
 */

/* test tlv get return */
static int test_t2l1n_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L1N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFF => -EINVAL */
    t = (1<<16);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1,1;12,1,1;00] t->3 => off-2, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t2l1n_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L1N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;12,2,12;00] t==NULL => off-2 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-2)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,1,1;12,2,12;00] t->0x0001 => 4, t==0x0001, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;12,2,12] t->0x0001 => 4, t==0x0001, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;12,2,12;00] t->0 => 4, t==0x0001, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;12,2,12] t->0 => 4, t==0x0001, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;12,2,12;00] t->0x0102 => off-2, t==0x0102, l==2 */
    t = 0x102;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0x102 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;12,2,12] t->0x0102 => off-2, t==0x0102, l==2 */
    t = 0x102;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 0x102 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;12,6,123456;00] t->0x0102, l->4 => off-2, t==0x0102, l==6 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0x102;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0x0102 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;12,6,123456] t->0x0102, l->4 => off-2, t==0x0102, l==6 */
    t = 0x102;
    l = 4;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 0x0102 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;12,2,12;01,3,123;00] t->1 => off-2, t==01, l==3 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,1,1;12,2,12;01,3,123] t->12 => off-2, t==02, l==2 */
    t = 0x102;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 0x0102 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t2l1n_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L1N;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;12,6,123456;23,2,12;34,4,1234;45,0;0] */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 4;
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-2;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 0x0001:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 0x0102:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0203:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0304:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0405:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 01,1,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0001 || l != 1 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 12,6,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0102 || l != 6 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 23,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0203 || l != 2 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 34,4,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0304 || l != 4 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 45,0 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0405 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 00 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t2l1n_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L1N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFF => -EINVAL */
    t = (1<<16);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFF => -EINVAL */
    t = 1;
    l = (1<<8);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;00,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;00] t==0, l==1 => 4 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 4)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[11,1,1;00] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0x0101;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t2l1n_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L1N;
    unsigned int t;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=01, l=1, v=1 */
    t = 1;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 1;
    tmp[off+3] = 1;
    ret = libtlv_put(opt, buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* init+fini: t=2, l=3, v=123 */
    t = 2;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 3;
    memcpy(&tmp[off+3], "123", 3);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != 3 || buf[0] || buf[1] || buf[2])
        RETURN_ERROR(ERROR_PUT);
    memcpy(buf+ret, "123", 3);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != 3)
        RETURN_ERROR(ERROR_PUT);
    ret += 3;
    buf += ret;
    len -= ret;
    off += ret;

    /* t=3, l=4, v=123\0 */
    t = 3;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 4;
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt, buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=4, l=5, v=12345 */
    t = 4;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 5;
    memcpy(&tmp[off+3], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, tmp[off+2], &tmp[off+3]);
    if (ret != off + 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    t = 4;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 6;
    memcpy(&tmp[off+3], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, tmp[off+2], &tmp[off+3]);
    if (ret != off + 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t2l1n: t=2 l=1 no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN t2l1p: t=2 l=1 with padding
 */

/* test tlv get return */
static int test_t2l1p_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L1P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFEFF => -EINVAL */
    t = 0xFF00;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,ff], t->1 => 2, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,00], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1,1;ff,12,1,1;ff;00] t->3 => off-2, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t2l1p_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L1P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;ff;12,2,12;ff;00] t==NULL => off-2 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-2)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,1,1;ff;12,2,12;ff;00] t->0x0001 => 4, t==0x0001, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;12,2,12;ff] t->0x0001 => 4, t==0x0001, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;12,2,12;ff;00] t->0 => 4, t==0x0001, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;12,2,12;ff] t->0 => 4, t==0x0001, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;12,2,12;ff;00] t->0x0102 => off-3, t==0x0102, l==2 */
    t = 0x102;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-3 || t != 0x102 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;ff;12,2,12;ff] t->0x0102 => off-3, t==0x0102, l==2 */
    t = 0x102;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-3 || t != 0x102 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;ff;12,6,123456;ff;00] t->0x0102, l->4 => off-3, t==0x0102, l==6 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0x102;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-3 || t != 0x0102 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;ff;12,6,123456;ff] t->0x0102, l->4 => off-3, t==0x0102, l==6 */
    t = 0x102;
    l = 4;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-3 || t != 0x0102 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;ff;12,2,12;ff;01,3,123;ff;00] t->1 => off-2, t==01, l==3 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,1,1;ff;12,2,12;01,3,123;ff] t->12 => off-2, t==02, l==2 */
    t = 0x102;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 0x0102 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t2l1p_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L1P;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;01,1,1;ff;12,6,123456;23,2,12;34,4,1234;ff;45,0;ff;ff;0] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 0xff;
    buf[off++] = 4;
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-2;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 0x0001:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 0x0102:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0203:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0304:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0405:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* ff;01,1,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0001 || l != 1 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;12,6,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0102 || l != 6 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 23,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0203 || l != 2 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 34,4,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0304 || l != 4 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* ff;45,0 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0405 || l != 0 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;00 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t2l1p_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L1P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFEFF => -EINVAL */
    t = 0xFF00;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFF => -EINVAL */
    t = 1;
    l = (1<<8);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,1,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;ff;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;00,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1,1;ff;00] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[ff;11,1,1;ff;00] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0x0101;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t2l1p_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L1P;
    unsigned int t, p = 0;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align l to 8 */
    tmp[off++] = 0xff; // 1
    tmp[off++] = 0xff; // 2
    tmp[off++] = 0xff; // 3
    tmp[off++] = 0xff; // 4
    tmp[off++] = 0xff; // 5
    p = 5;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=01, l=1, v=1 */
    t = 1;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 1;
    tmp[off+3] = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN8B,
                     buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != p + 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align l to 16 */
    tmp[off++] = 0xff; // 10
    tmp[off++] = 0xff; // 11
    tmp[off++] = 0xff; // 12
    tmp[off++] = 0xff; // 13
    p = 4;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* init+fini: t=2, l=3, v=123 */
    t = 2;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 3;
    memcpy(&tmp[off+3], "123", 3);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN16B | LIBTLV_OPT_PUT_INIT,
                     buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != p + 3 || buf[p+0] || buf[p+1] || buf[p+2])
        RETURN_ERROR(ERROR_PUT);
    memcpy(&buf[p+3], "123", 3);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN16B | LIBTLV_OPT_PUT_FINI,
                     buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != p + 3)
        RETURN_ERROR(ERROR_PUT);
    ret += tmp[off+2];
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align l to 32 */
    tmp[off++] = 0xff; // 20
    tmp[off++] = 0xff; // 21
    tmp[off++] = 0xff; // 22
    tmp[off++] = 0xff; // 23
    tmp[off++] = 0xff; // 24
    tmp[off++] = 0xff; // 25
    tmp[off++] = 0xff; // 26
    tmp[off++] = 0xff; // 27
    tmp[off++] = 0xff; // 28
    tmp[off++] = 0xff; // 29
    p = 10;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=3, l=4, v=123\0 */
    t = 3;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 4;
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN32B,
                     buf, len, t, tmp[off+2], &tmp[off+3]);
    if (ret != p + 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=4, l=5, v=12345 */
    t = 4;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 5;
    memcpy(&tmp[off+3], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, tmp[off+2], &tmp[off+3]);
    if (ret != off + 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    t = 4;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    tmp[off+2] = 6;
    memcpy(&tmp[off+3], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, tmp[off+2], &tmp[off+3]);
    if (ret != off + 3 + tmp[off+2])
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t2l1p: t=2 l=1 with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

/*
 * BEGIN t1l2n: t=1 l=2 no padding
 */

/* test tlv get return */
static int test_t1l2n_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L2N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFF => -EINVAL */
    t = (1<<8);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,11,0x256] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 256);
    off += 256;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;2,11,0x257;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 257);
    off += 257;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t1l2n_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L2N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,01,1;2,12,'2'x258;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[1,01,1;2,12,'2'x258;0] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;2,12,'2'x258] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;2,12,'2'x258;0] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;2,12,'2'x258] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;2,12,'2'x258;0] t->2 => off-1, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+1 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[1,01,1;2,12,'2'x258] t->2 => off-1, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+1 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[1,01,1;2,12,'2'x258;0] t->2, l->4 => off-1, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,01,1;2,12,'2'x258] t->2, l->4 => off-1, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,01,1;2,12,'2'x258;1,03,123;0] t->1 => off-1, t==1, l==3 */
    buf[off-1] = 1;
    buf[off++] = 0;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[1,01,1;2,12,'2'x258;1,03,123] t->2 => off-1, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+1 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t1l2n_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L2N;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,01,1;2,06,123456;3,12,'2'x258;4,04,1234;5,00;0] */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 3;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 4;
    buf[off++] = 0;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 1,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 2,06,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 6 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 0x0102 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t1l2n_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L2N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFF => -EINVAL */
    t = (1<<8);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFF => -EINVAL */
    t = 1;
    l = (1<<16);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==0, l==1 => 4 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 4)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[1,01,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t1l2n_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L2N;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=1, l=1, v=1 */
    tmp[off+0] = 1;
    l = 1;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    tmp[off+3] = 1;
    ret = libtlv_put(opt, buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* init+fini: t=2, l=13, v='2'x259 */
    tmp[off+0] = 2;
    l = 0x0103;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memset(&tmp[off+3], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != 3 || buf[0] || buf[1] || buf[2])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[3], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != 3)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

    /* t=3, l=4, v=123\0 */
    tmp[off+0] = 3;
    l = 4;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt, buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=4, l=5, v=12345 */
    tmp[off+0] = 4;
    l = 5;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memcpy(&tmp[off+3], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    tmp[off+0] = 4;
    l = 6;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memcpy(&tmp[off+3], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t1l2n: t=1 l=2 no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN t1l2p: t=1 l=2 with padding
 */

/* test tlv get return */
static int test_t1l2p_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L2P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFE => -EINVAL */
    t = 0xFF;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,11,0x256] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 256);
    off += 256;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,11,0x256] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 256);
    off += 256;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,01,1;ff;2,11,0x257;ff;ff;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 257);
    off += 257;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t1l2p_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L2P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 0xff;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;0] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;ff;2,12,'2'x258;ff] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;0] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;ff;2,12,'2'x258;ff] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;0] t->2 => off-2, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+1 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff] t->2 => off-2, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+1 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;0] t->2, l->4 => off-2, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff] t->2, l->4 => off-2, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;1,03,123;ff;0] t->1 => off-1, t==1, l==3 */
    buf[off-1] = 1;
    buf[off++] = 0;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[1,01,1;ff;2,12,'2'x258;ff;1,03,123;ff] t->2 => off-1, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+1 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t1l2p_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L2P;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;1,01,1;ff;ff;2,06,123456;ff;3,12,'2'x258;4,04,1234;5,00;ff;ff;0] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 0;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0xff;
    buf[off++] = 3;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 4;
    buf[off++] = 0;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[5])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* ff;1,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;2,06,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 6 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[5])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* ff;3,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 0x0102 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t1l2p_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1L2P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFE => -EINVAL */
    t = 0xFF;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFF => -EINVAL */
    t = 1;
    l = (1<<16);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;ff;ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;ff;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;0,00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;0] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[ff;1,01,1;ff;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t1l2p_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1L2P;
    unsigned int l, p = 0;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align v to 2 */
    // 1
    p = 0;
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

    /* t=1, l=1, v=1 */
    tmp[off+0] = 1;
    l = 1;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    tmp[off+3] = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN2B,
                     buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != p + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align v to 4 */
    // 5
    p = 0;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* ini+fini: t=2, l=13, v='2'x259 */
    tmp[off+0] = 2;
    l = 0x0103;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memset(&tmp[off+3], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN4B | LIBTLV_OPT_PUT_INIT,
                     buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != p + 3 || buf[p] || buf[p+1] || buf[p+2])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[p+3], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN4B | LIBTLV_OPT_PUT_FINI,
                     buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != p + 3)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align v to 8 */
    tmp[off++] = 0xff; // 267
    tmp[off++] = 0xff; // 268
    p = 2;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=3, l=4, v=123\0 */
    tmp[off+0] = 3;
    l = 4;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN8B,
                     buf, len, tmp[off+0], l, &tmp[off+3]);
    if (ret != p + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=4, l=5, v=12345 */
    tmp[off+0] = 4;
    l = 5;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memcpy(&tmp[off+3], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    tmp[off+0] = 4;
    l = 6;
    tmp[off+1] = (l >> 8);
    tmp[off+2] = (l & 0xFF);
    memcpy(&tmp[off+3], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, tmp[off+0], l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t1l2p: t=1 l=2 with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

/*
 * BEGIN t2l2n: t=2 l=2 no padding
 */

/* test tlv get return */
static int test_t2l2n_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L2N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFF => -EINVAL */
    t = (1<<16);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t->n => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,00], t->1 => 4, t==1 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,11,0x256] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 256);
    off += 256;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;02,11,0x257;00] t->3 => off-2, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 257);
    off += 257;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t2l2n_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L2N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,01,1;02,12,'2'x258;00] t==NULL => off-2 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 0;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-2)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,01,1;02,12,'2'x258;00] t->1 => 5, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;02,12,'2'x258] t->1 => 5, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;02,12,'2'x258;00] t->0 => 5, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;02,12,'2'x258] t->0 => 5, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;02,12,'2'x258;00] t->2 => off-2, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+2 > len)
        RETURN_ERROR(ERROR_GET);
    tmp[l] = 0;
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[01,01,1;02,12,'2'x258] t->2 => off-2, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+2 > len)
        RETURN_ERROR(ERROR_GET);
    tmp[l] = 0;
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[01,01,1;02,12,'2'x258;00] t->2, l->4 => off-2, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,01,1;02,12,'2'x258] t->2, l->4 => off-2, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,01,1;02,12,'2'x258;01,03,123;00] t->1 => off-2, t==1, l==3 */
    buf[off-2] = 0;
    buf[off-1] = 1;
    buf[off++] = 0;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,01,01;2,12,'2'x258;01,03,123] t->2 => off-2, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+2 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t2l2n_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L2N;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,01,1;12,06,123456;23,12,'2'x258;34,04,1234;45,00;00] */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 0;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 4;
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-2;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 0x0001:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 0x0102:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0203:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0304:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0405:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 01,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0001 || l != 1 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 12,06,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0102 || l != 6 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 23,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0203 || l != 0x0102 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 34,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0304 || l != 4 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 45,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0405 || l != 0 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 00 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t2l2n_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L2N;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFF => -EINVAL */
    t = (1<<16);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFF => -EINVAL */
    t = 1;
    l = (1<<16);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;00,00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;00] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[11,01,1;00] t==0x0101, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0x0101;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t2l2n_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L2N;
    unsigned int t, l;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=01, l=1, v=1 */
    t = 1;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 1;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    tmp[off+4] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+4]);
    if (ret != 4 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* t=12, l=13, v='2'x259 */
    t = 0x0102;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 0x0103;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memset(&tmp[off+4], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, l, &tmp[off+4]);
    if (ret != 4 || buf[0] || buf[1] || buf[2] || buf[3])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[4], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, l, &tmp[off+4]);
    if (ret != 4)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

    /* t=23, l=4, v=123\0 */
    t = 0x0203;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 4;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memcpy(&tmp[off+4], "123", 4);
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+4]);
    if (ret != 4 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=34, l=5, v=12345 */
    t = 0x0304;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 5;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memcpy(&tmp[off+4], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+4]);
    if (ret != off + 4 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=34, l=6, v=123456 */
    t = 0x0304;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 6;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memcpy(&tmp[off+4], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+4]);
    if (ret != off + 4 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t2l2n: t=2 l=2 no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN t2l2p: t=2 l=2 with padding
 */

/* test tlv get return */
static int test_t2l2p_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L2P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFEFF => -EINVAL */
    t = 0xFF00;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;ff], t->1 => 2, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t->n => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;00], t->n => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,00], t->1 => 4, t==1 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,11,0x256] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 256);
    off += 256;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;02,11,0x257;ff;00] t->3 => off-2, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 1;
    memset(&buf[off], 0, 257);
    off += 257;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t2l2p_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L2P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,01,1;ff;02,12,'2'x258;ff;00] t==NULL => off-2 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-2)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,01,1;ff;02,12,'2'x258;ff;00] t->1 => 5, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;ff;02,12,'2'x258;ff] t->1 => 5, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;ff;02,12,'2'x258;ff;00] t->0 => 5, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;ff;02,12,'2'x258;ff] t->0 => 5, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 5 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,01,1;ff;02,12,'2'x258;ff;00] t->2 => off-3, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+2 > len)
        RETURN_ERROR(ERROR_GET);
    tmp[l] = 0;
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[01,01,1;ff;02,12,'2'x258;ff] t->2 => off-3, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+2 > len)
        RETURN_ERROR(ERROR_GET);
    tmp[l] = 0;
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    /* buf==[01,01,1;ff;02,12,'2'x258;ff;00] t->2, l->4 => off-3, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,01,1;ff;02,12,'2'x258;ff] t->2, l->4 => off-3, t==2, l==0x0102 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (tmp[4] || memspn(tmp, '2', 4) != 4)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,01,1;ff;02,12,'2'x258;01,ff;03,123;ff;00] t->1 => off-2, t==1, l==3 */
    buf[off-2] = 0;
    buf[off-1] = 1;
    buf[off++] = 0;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,01,01;ff;2,12,'2'x258;ff;01,03,123;ff] t->2 => off-2, t==2, l==0x0102 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 0x0102)
        RETURN_ERROR(ERROR_GET);
    if (l+2 > len)
        RETURN_ERROR(ERROR_GET);
    if (memspn(tmp, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l+1);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t2l2p_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L2P;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;01,01,1;ff;12,06,123456;23,12,'2'x258;34,04,1234;ff;45,00;ff;ff;00] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 1;
    buf[off++] = 2;
    memset(&buf[off], '2', 258);
    off += 258;
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 0;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 0xff;
    buf[off++] = 4;
    buf[off++] = 5;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-2;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 0x0001:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[5])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 0x0102:
                if (l != 6 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[5])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "123456", 6))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0203:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0304:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x0405:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* ff;01,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0001 || l != 1 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[5])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;12,06,123456 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0102 || l != 6 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[5])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "123456", 6))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 23,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0203 || l != 0x0102 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 34,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0304 || l != 4 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* ff;45,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 5)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x0405 || l != 0 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;00 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t2l2p_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2L2P;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFEFF => -EINVAL */
    t = 0xFF00;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFF => -EINVAL */
    t = 1;
    l = (1<<16);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;ff;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;00,00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;ff;00,00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;00] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,01,1;ff;00] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 6)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[11,01,1;ff;00] t==0x0101, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0x0101;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t2l2p_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2L2P;
    unsigned int t, l, p = 0;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align l to 2 */
    tmp[off++] = 0xff; // 1
    p = 1;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=01, l=1, v=1 */
    t = 1;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 1;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    tmp[off+4] = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN2B,
                     buf, len, t, l, &tmp[off+4]);
    if (ret != p + 4 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align l to 4 */
    tmp[off++] = 0xff; // 7
    tmp[off++] = 0xff; // 8
    tmp[off++] = 0xff; // 9
    p = 3;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=12, l=13, v='2'x259 */
    t = 0x0102;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 0x0103;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memset(&tmp[off+4], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN4B | LIBTLV_OPT_PUT_INIT,
                     buf, len, t, l, &tmp[off+4]);
    if (ret != p + 4 || buf[p] || buf[p+1] || buf[p+2] || buf[p+3])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[p+4], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNL | LIBTLV_OPT_ALN4B | LIBTLV_OPT_PUT_FINI,
                     buf, len, t, l, &tmp[off+4]);
    if (ret != p + 4)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align t to 16 */
    tmp[off++] = 0xff; // 273
    tmp[off++] = 0xff; // 274
    tmp[off++] = 0xff; // 275
    tmp[off++] = 0xff; // 276
    tmp[off++] = 0xff; // 277
    tmp[off++] = 0xff; // 278
    tmp[off++] = 0xff; // 279
    tmp[off++] = 0xff; // 280
    tmp[off++] = 0xff; // 281
    tmp[off++] = 0xff; // 282
    tmp[off++] = 0xff; // 283
    tmp[off++] = 0xff; // 284
    tmp[off++] = 0xff; // 285
    tmp[off++] = 0xff; // 286
    tmp[off++] = 0xff; // 287
    p = 15;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=23, l=4, v=123\0 */
    t = 0x0203;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 4;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memcpy(&tmp[off+4], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNT | LIBTLV_OPT_ALN16B,
                     buf, len, t, l, &tmp[off+4]);
    if (ret != p + 4 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=34, l=5, v=12345 */
    t = 0x0304;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 5;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memcpy(&tmp[off+4], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+4]);
    if (ret != off + 4 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=34, l=6, v=123456 */
    t = 0x0304;
    tmp[off+0] = (t >> 8);
    tmp[off+1] = (t & 0xFF);
    l = 6;
    tmp[off+2] = (l >> 8);
    tmp[off+3] = (l & 0xFF);
    memcpy(&tmp[off+4], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+4]);
    if (ret != off + 4 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t2l2p: t=2 l=2 with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

#if     ENABLE_LIBTLV_VARLEN_SUPPORT
/*
 * BEGIN t1lvn: t=1 l=v no padding
 */

/* test tlv get return */
static int test_t1lvn_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1LVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFF => -EINVAL */
    t = (1<<8);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;2,0001,1;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x01;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t1lvn_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1LVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,1,1;2,02,12;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[1,1,1;2,02,12;0] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,02,12] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,02,12;0] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,02,12] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;2,02,12;0] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[1,1,1;2,02,12] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[1,1,1;2,006,123456;0] t->2, l->4 => off-1, t==2, l==6 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,1,1;2,006,123456] t->2, l->4 => off-1, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[1,1,1;2,0002,12;1,3,123;0] t->1 => off-1, t==1, l==3 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[1,1,1;2,0002,12;1,3,123] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t1lvn_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1LVN;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,01,1;2,12,'2'x258;3,2,12;4,04,1234;5,00;0] */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 2;
    l = 0x0102;
    buf[off++] = 0x80 | (l >> 7);
    buf[off++] = 0x7f & l;
    memset(&buf[off], '2', l);
    off += l;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 4;
    buf[off++] = 0x80;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0x80;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 1,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 2,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 0x0102 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t1lvn_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1LVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFF => -EINVAL */
    t = (1<<8);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFFFFF => -EINVAL */
    t = 1;
    l = (1U<<28);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,00] t==2, l==1 => 7 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 7 || buf[4] != 2 || buf[5] != 1 || buf[6] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==0, l==1 => 4 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 4)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[1,01,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t1lvn_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1LVN;
    unsigned int t, l;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=1, l=1, v=1 */
    t = 1;
    tmp[off+0] = t;
    l = 1;
    tmp[off+1] = 1;
    tmp[off+2] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+2]);
    if (ret != 2 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* t=2, l=13, v='2'x259 */
    t = 2;
    tmp[off+0] = t;
    l = 0x0103;
    tmp[off+1] = 0x80;
    tmp[off+2] = 0x80;
    tmp[off+3] = 0x80 | (l >> 7);
    tmp[off+4] = 0x7f & l;
    memset(&tmp[off+5], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, l, &tmp[off+5]);
    if (ret != 5 || buf[0] || buf[1] || buf[2] || buf[3] || buf[4])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[5], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, l, &tmp[off+5]);
    if (ret != 5)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

    /* t=3, l=4, v=123\0 */
    t = 3;
    tmp[off+0] = t;
    l = 4;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "123", 4);
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+2]);
    if (ret != 2 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=4, l=5, v=12345 */
    t = 4;
    tmp[off+0] = t;
    l = 5;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    t = 4;
    tmp[off+0] = t;
    l = 6;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t1lvn: t=1 l=v no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN t1lvp: t=1 l=v with padding
 */

/* test tlv get return */
static int test_t1lvp_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1LVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFE => -EINVAL */
    t = 0xFF;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1,1;ff;2,0001,1;ff;ff;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x01;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t1lvp_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1LVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,1,1;ff;2,02,12;ff;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[1,1,1;ff;2,02,12;ff;0] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,02,12;ff] t->1 => 3, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,02,12;ff;0] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,02,12;ff] t->0 => 3, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 3 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[1,1,1;ff;2,02,12;ff;0] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[1,1,1;ff;2,02,12;ff] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[ff;1,1,1;ff;2,006,123456;0] t->2, l->4 => off-1, t==2, l==6 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[ff;1,1,1;ff;2,006,123456] t->2, l->4 => off-1, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[ff;1,1,1;ff;2,0002,12;ff;1,3,123;0] t->1 => off-1, t==1, l==3 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[ff;1,1,1;ff;2,0002,12;ff;1,3,123] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t1lvp_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1LVP;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;1,01,1;ff;ff;2,12,'2'x258;3,2,12;4,04,1234;5,00;ff;ff;0] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 2;
    l = 0x0102;
    buf[off++] = 0x80 | (l >> 7);
    buf[off++] = 0x7f & l;
    memset(&buf[off], '2', l);
    off += l;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 4;
    buf[off++] = 0x80;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0x80;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[5])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* ff;1,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;2,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 0x0102 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[5])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t1lvp_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T1LVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFE => -EINVAL */
    t = 0xFF;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFFFFF => -EINVAL */
    t = 1;
    l = (1U<<28);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,00] t==2, l==1 => 7 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 7 || buf[4] != 2 || buf[5] != 1 || buf[6] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;ff;0,00] t==2, l==1 => 10 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 10 || buf[7] != 2 || buf[8] != 1 || buf[9] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;ff;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;ff;0] t==0, l==1 => 4 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 7)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[ff;1,01,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t1lvp_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T1LVP;
    unsigned int t, l, p = 0;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

    /* t=1, l=1, v=1 */
    t = 1;
    tmp[off+0] = t;
    l = 1;
    tmp[off+1] = 1;
    tmp[off+2] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+2]);
    if (ret != 2 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align v to 8 */
    tmp[off++] = 0xff; // 4
    tmp[off++] = 0xff; // 5
    tmp[off++] = 0xff; // 6
    tmp[off++] = 0xff; // 7
    tmp[off++] = 0xff; // 8
    tmp[off++] = 0xff; // 9
    tmp[off++] = 0xff; // 10
    p = 7;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=2, l=13, v='2'x259 */
    t = 2;
    tmp[off+0] = t;
    l = 0x0103;
    tmp[off+1] = 0x80;
    tmp[off+2] = 0x80;
    tmp[off+3] = 0x80 | (l >> 7);
    tmp[off+4] = 0x7f & l;
    memset(&tmp[off+5], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN8B | LIBTLV_OPT_PUT_INIT,
                     buf, len, t, l, &tmp[off+5]);
    if (ret != p + 5 || buf[0] || buf[1] || buf[2] || buf[3] || buf[4])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[p + 5], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN8B | LIBTLV_OPT_PUT_FINI,
                     buf, len, t, l, &tmp[off+5]);
    if (ret != p + 5)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret - p;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align v to 16 */
    tmp[off++] = 0xff; // 275
    tmp[off++] = 0xff; // 276
    tmp[off++] = 0xff; // 277
    tmp[off++] = 0xff; // 278
    tmp[off++] = 0xff; // 279
    tmp[off++] = 0xff; // 280
    tmp[off++] = 0xff; // 281
    tmp[off++] = 0xff; // 282
    tmp[off++] = 0xff; // 283
    tmp[off++] = 0xff; // 284
    tmp[off++] = 0xff; // 285
    p = 11;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=3, l=4, v=123\0 */
    t = 3;
    tmp[off+0] = t;
    l = 4;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN16B,
                     buf, len, t, l, &tmp[off+2]);
    if (ret != p + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=4, l=5, v=12345 */
    t = 4;
    tmp[off+0] = t;
    l = 5;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    t = 4;
    tmp[off+0] = t;
    l = 6;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t1lvp: t=1 l=v with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

/*
 * BEGIN t2lvn: t=2 l=v no padding
 */

/* test tlv get return */
static int test_t2lvn_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2LVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFF => -EINVAL */
    t = (1<<16);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1,1;02,0001,1;00] t->3 => off-2, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x01;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t2lvn_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2LVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;02,02,12;0] t==NULL => off-2 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-2)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,1,1;02,02,12;00] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12;00] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12;00] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;02,02,12] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;02,006,123456;00] t->2, l->4 => off-2, t==2, l==6 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;02,006,123456] t->2, l->4 => off-2, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;02,0002,12;01,3,123;00] t->1 => off-2, t==1, l==3 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,1,1;02,0002,12;01,3,123] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t2lvn_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2LVN;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,01,1;02,12,'2'x258;03,2,12;04,04,1234;05,00;00] */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 2;
    l = 0x0102;
    buf[off++] = 0x80 | (l >> 7);
    buf[off++] = 0x7f & l;
    memset(&buf[off], '2', l);
    off += l;
    buf[off++] = 0;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 4;
    buf[off++] = 0x80;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 0;
    buf[off++] = 5;
    buf[off++] = 0x80;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-2;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 01,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 02,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 0x0102 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 03,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 04,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 05,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 00 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t2lvn_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2LVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFF => -EINVAL */
    t = (1<<16);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFFFFF => -EINVAL */
    t = 1;
    l = (1U<<28);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00,00] t==2, l==1 => 9 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 9 || buf[5] != 0 || buf[6] != 2 || buf[7] != 1 || buf[8] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[01,01,1;00] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t2lvn_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2LVN;
    unsigned int t, l;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=01, l=1, v=1 */
    t = 1;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 1;
    tmp[off+2] = l;
    tmp[off+3] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+3]);
    if (ret != 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* t=02, l=13, v='2'x259 */
    t = 2;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 0x0103;
    tmp[off+2] = 0x80;
    tmp[off+3] = 0x80;
    tmp[off+4] = 0x80 | (l >> 7);
    tmp[off+5] = 0x7f & l;
    memset(&tmp[off+6], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, l, &tmp[off+6]);
    if (ret != 6)
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[6], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, l, &tmp[off+6]);
    if (ret != 6)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

    /* t=3, l=4, v=123\0 */
    t = 3;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 4;
    tmp[off+2] = l;
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+3]);
    if (ret != 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=04, l=5, v=12345 */
    t = 4;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 5;
    tmp[off+2] = l;
    memcpy(&tmp[off+3], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=04, l=6, v=123456 */
    t = 4;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 6;
    tmp[off+2] = 6;
    memcpy(&tmp[off+3], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t2lvn: t=2 l=v no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN t2lvp: t=2 l=v with padding
 */

/* test tlv get return */
static int test_t2lvp_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2LVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFEFF => -EINVAL */
    t = 0xFF00;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,ff], t->1 => 2, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,00], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[11,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;11,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1,1;ff;02,0001,1;ff;00] t->3 => off-2, t==0 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x01;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1,1;ff;02,0001,1;ff] t->3 => off-2, t==0 */
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_t2lvp_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2LVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;ff;02,02,12;ff;0] t==NULL => off-2 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-2)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,1,1;ff;02,02,12;ff;00] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;00;ff] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff;00] t->2 => off-3, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;ff;02,02,12;ff] t->2 => off-3, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;ff;02,006,123456;ff;00] t->2, l->4 => off-3, t==2, l==6 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;ff;02,006,123456;ff] t->2, l->4 => off-3, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-2, &t, &l, tmp);
    if (ret != off-3 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;ff;02,0002,12;01,3,123;ff;00] t->1 => off-2, t==1, l==3 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,1,1;ff;02,0002,12;01,3,123;ff] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-2, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_t2lvp_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2LVP;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;01,01,1;ff;02,12,'2'x258;03,2,12;04,04,1234;ff;05,00;ff;ff;00] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 2;
    l = 0x0102;
    buf[off++] = 0x80 | (l >> 7);
    buf[off++] = 0x7f & l;
    memset(&buf[off], '2', l);
    off += l;
    buf[off++] = 0;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    buf[off++] = 4;
    buf[off++] = 0x80;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 5;
    buf[off++] = 0x80;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-2;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[5])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[5])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 4:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 5+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* ff;01,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[5])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;02,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 0x0102 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[5])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 03,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 04,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 4 || l != 4 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* ff;05,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 5+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;00 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_t2lvp_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_T2LVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFEFF => -EINVAL */
    t = 0xFF00;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFFFFF => -EINVAL */
    t = 1;
    l = (1U<<28);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;00], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;00] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00,00] t==2, l==1 => 9 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 9 || buf[5] != 0 || buf[6] != 2 || buf[7] != 1 || buf[8] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;00,00] t==2, l==1 => 10 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 10 || buf[6] != 0 || buf[7] != 2 || buf[8] != 1 || buf[9] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;00,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;00] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;00] t==0, l==1 => 6 */
    off = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 6)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[ff;01,01,1;ff;00] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_t2lvp_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_T2LVP;
    unsigned int t, l, p = 0;;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

    /* t=01, l=1, v=1 */
    t = 1;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 1;
    tmp[off+2] = l;
    tmp[off+3] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+3]);
    if (ret != 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

    /* t=02, l=13, v='2'x259 */
    t = 2;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 0x0103;
    tmp[off+2] = 0x80;
    tmp[off+3] = 0x80;
    tmp[off+4] = 0x80 | (l >> 7);
    tmp[off+5] = 0x7f & l;
    memset(&tmp[off+6], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, l, &tmp[off+6]);
    if (ret != 6 || buf[0] || buf[1] || buf[2] || buf[3] || buf[4] || buf[5])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[6], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, l, &tmp[off+6]);
    if (ret != 6)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align t to 32 */
    tmp[off++] = 0xff; // 271
    tmp[off++] = 0xff; // 272
    tmp[off++] = 0xff; // 273
    tmp[off++] = 0xff; // 274
    tmp[off++] = 0xff; // 275
    tmp[off++] = 0xff; // 276
    tmp[off++] = 0xff; // 277
    tmp[off++] = 0xff; // 278
    tmp[off++] = 0xff; // 279
    tmp[off++] = 0xff; // 280
    tmp[off++] = 0xff; // 281
    tmp[off++] = 0xff; // 282
    tmp[off++] = 0xff; // 283
    tmp[off++] = 0xff; // 284
    tmp[off++] = 0xff; // 285
    tmp[off++] = 0xff; // 286
    tmp[off++] = 0xff; // 287
    p = 17;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=3, l=4, v=123\0 */
    t = 3;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 4;
    tmp[off+2] = l;
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNT | LIBTLV_OPT_ALN32B,
                     buf, len, t, l, &tmp[off+3]);
    if (ret != p + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=04, l=5, v=12345 */
    t = 4;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 5;
    tmp[off+2] = l;
    memcpy(&tmp[off+3], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=04, l=6, v=123456 */
    t = 4;
    tmp[off+0] = 0;
    tmp[off+1] = t;
    l = 6;
    tmp[off+2] = 6;
    memcpy(&tmp[off+3], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+3]);
    if (ret != off + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END t2lvp: t=2 l=v with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

/*
 * BEGIN tvlvn: t=v l=v no padding
 */

/* test tlv get return */
static int test_tvlvn_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_TVLVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFFFFF => -EINVAL */
    t = (1<<28);
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0x80], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1,1;02,0001,1;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x01;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_tvlvn_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_TVLVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;02,02,12;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,1,1;02,02,12;0] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12;0] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;02,02,12;0] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;02,02,12] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;02,006,123456;0] t->2, l->4 => off-1, t==2, l==6 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;02,006,123456] t->2, l->4 => off-1, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[01,1,1;02,0002,12;1,3,123;0] t->1 => off-1, t==1, l==3 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[01,1,1;02,0002,12;1,3,123] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_tvlvn_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_TVLVN;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[1,01,1;02,12,'2'x258;3,2,12;4444,04,1234;5,00;0] */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 2;
    l = 0x0102;
    buf[off++] = 0x80 | (l >> 7);
    buf[off++] = 0x7f & l;
    memset(&buf[off], '2', l);
    off += l;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    t = 0x04040404;
    buf[off++] = 0x80 | (t >> 21);
    buf[off++] = 0x80 | (t >> 14);
    buf[off++] = 0x80 | (t >>  7);
    buf[off++] = 0x7f & t;
    buf[off++] = 0x80;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0x80;
    buf[off++] = 0;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[3])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x04040404:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 6+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[6])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* 1,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[3])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 02,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 0x0102 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4444,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x04040404 || l != 4 || ret != 6+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[6])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* 0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_tvlvn_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_TVLVN;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFFFFFFF => -EINVAL */
    t = (1U<<28);
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFFFFF => -EINVAL */
    t = 1;
    l = (1U<<28);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0x80,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,00] t==2, l==1 => 7 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 7 || buf[4] != 2 || buf[5] != 1 || buf[6] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;0,00] t==2, l==1 => 8 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 8 || buf[5] != 2 || buf[6] != 1 || buf[7] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==0, l==1 => 4 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 4)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[0001,01,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_tvlvn_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_TVLVN;
    unsigned int t, l;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* t=1, l=1, v=1 */
    t = 1;
    tmp[off+0] = t;
    l = 1;
    tmp[off+1] = 1;
    tmp[off+2] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+2]);
    if (ret != 2 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* t=12, l=13, v='2'x259 */
    t = 0x0102;
    tmp[off+0] = 0x80;
    tmp[off+1] = 0x80;
    tmp[off+2] = 0x80 | (t >> 7);
    tmp[off+3] = 0x7f & t;
    l = 0x0103;
    tmp[off+4] = 0x80;
    tmp[off+5] = 0x80;
    tmp[off+6] = 0x80 | (l >> 7);
    tmp[off+7] = 0x7f & l;
    memset(&tmp[off+8], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, l, &tmp[off+8]);
    if (ret != 8 || buf[0] || buf[1] || buf[2] || buf[3] || buf[4] || buf[5] || buf[6] || buf[7])
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[8], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, l, &tmp[off+8]);
    if (ret != 8)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

    /* t=13, l=4, v=123\0 */
    t = 0x0103;
    tmp[off+0] = 0x80 | (t >> 7);
    tmp[off+1] = 0x7f & t;
    l = 4;
    tmp[off+2] = l;
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+3]);
    if (ret != 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* append: t=4, l=5, v=12345 */
    t = 4;
    tmp[off+0] = t;
    l = 5;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    t = 4;
    tmp[off+0] = t;
    l = 6;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END tvlvn: t=v l=v no padding
 */

#if     ENABLE_LIBTLV_PADDING_SUPPORT
/*
 * BEGIN tvlvp: t=v l=v with padding
 */

/* test tlv get return */
static int test_tvlvp_getret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_TVLVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* size<0 => -E2BIG */
    ret = libtlv_get(opt, NULL, (size_t)-1, NULL, NULL, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_get(opt, NULL, (size_t)1, NULL, NULL, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFDFFFFF => -EINVAL */
    t = 0xFE00000;
    l = len;
    ret = libtlv_get(opt, buf, len, &t, &l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, l!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, &l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t==NULL, v!= NULL => -EINVAL */
    ret = libtlv_get(opt, buf, len, NULL, NULL, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t->1 => 0, t==0 */
    off = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t->1 => 0, t==0 */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 0 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff,0], t->1 => 1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0x80], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0x80], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01], t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,01] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,00001,1] t->n => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1,1;ff;02,0001,1;ff;ff;0] t->3 => off-1, t==0 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x01;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 3;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 0)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get input */
static int test_tvlvp_input(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_TVLVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[01,1,1;ff;02,02,12;ff;0] t==NULL => off-1 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 0;
    ret = libtlv_get(opt, buf, off, NULL, NULL, NULL);
    if (ret != off-1)
        RETURN_ERROR(ERROR_GET);

    /* buf==[01,1,1;ff;02,02,12;ff;0] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff] t->1 => 4, t==1, l==1 */
    t = 1;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff;0] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff] t->0 => 4, t==1, l==1 */
    t = 0;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != 4 || t != 1 || l != 1)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != 1)
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];

    /* buf==[01,1,1;ff;02,02,12;ff;0] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[01,1,1;ff;02,02,12;ff] t->2 => off-2, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (tmp[0] != '1' || tmp[1] != '2')
        RETURN_ERROR(ERROR_CMP);
    tmp[0] = ~tmp[0];
    tmp[1] = ~tmp[1];

    /* buf==[ff;01,1,1;ff;02,006,123456;ff;0] t->2, l->4 => off-2, t==2, l==6 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 6;
    memcpy(&buf[off], "123456", 6);
    off += 6;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[ff;01,1,1;ff;02,006,123456;ff] t->2, l->4 => off-2, t==2, l==6 */
    t = 2;
    l = 4;
    ret = libtlv_get(opt, buf, off-1, &t, &l, tmp);
    if (ret != off-2 || t != 2 || l != 6)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, 4);

    /* buf==[ff;01,1,1;ff;02,0002,12;ff;1,3,123;0] t->1 => off-1, t==1, l==3 */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 3;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = 0;
    t = 1;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off, &t, &l, tmp);
    if (ret != off-1 || t != 1 || l != 3)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "123", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    /* buf==[ff;01,1,1;ff;02,0002,12;1,3,123] t->2 => off-1, t==2, l==2 */
    t = 2;
    l = len;
    ret = libtlv_get(opt | LIBTLV_OPT_GET_LAST, buf, off-1, &t, &l, tmp);
    if (ret != off-1 || t != 2 || l != 2)
        RETURN_ERROR(ERROR_GET);
    if (memcmp(tmp, "12", l))
        RETURN_ERROR(ERROR_CMP);
    memset(tmp, 0, l);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv get next */
static int test_tvlvp_getnext(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_TVLVP;
    unsigned int t;
    unsigned int l;
    uint8_t     *v;

    memset(buf, 0xAA, len);
    memset(tmp, 0xBB, len);

    /* buf==[ff;1,01,1;ff;ff;02,12,'2'x258;3,2,12;4444,04,1234;5,00;ff;ff;0] */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 2;
    l = 0x0102;
    buf[off++] = 0x80 | (l >> 7);
    buf[off++] = 0x7f & l;
    memset(&buf[off], '2', l);
    off += l;
    buf[off++] = 3;
    buf[off++] = 2;
    buf[off++] = '1';
    buf[off++] = '2';
    t = 0x04040404;
    buf[off++] = 0x80 | (t >> 21);
    buf[off++] = 0x80 | (t >> 14);
    buf[off++] = 0x80 | (t >>  7);
    buf[off++] = 0x7f & t;
    buf[off++] = 0x80;
    buf[off++] = 4;
    buf[off++] = '1';
    buf[off++] = '2';
    buf[off++] = '3';
    buf[off++] = '4';
    buf[off++] = 5;
    buf[off++] = 0x80;
    buf[off++] = 0;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;

    ret = 0;
    len = off-1;

    /* loop */
    while (len > ret)
    {
        buf += ret;
        len -= ret;

        t = 0;
        l = 0;
        v = NULL;
        ret = libtlv_get(opt, buf, len, &t, &l, &v);
        if (ret < 0)
            RETURN_ERROR(ERROR_GET);
        if (t == 0)
            break;
        if (ret == 0)
            RETURN_ERROR(ERROR_GET);
        switch (t)
        {
            case 1:
                if (l != 1)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 4+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[4])
                    RETURN_ERROR(ERROR_GET);
                break;
            case 2:
                if (l != 0x0102 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 6+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[6])
                    RETURN_ERROR(ERROR_GET);
                if (memspn(v, '2', l) != l)
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 3:
                if (l != 2 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 2+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[2])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "12", 2))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 0x04040404:
                if (l != 4 || v == NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 6+l)
                    RETURN_ERROR(ERROR_GET);
                if (v != &buf[6])
                    RETURN_ERROR(ERROR_GET);
                if (memcmp(v, "1234", 4))
                    RETURN_ERROR(ERROR_CMP);
                break;
            case 5:
                if (l != 0 || v != NULL)
                    RETURN_ERROR(ERROR_GET);
                if (ret != 3+l)
                    RETURN_ERROR(ERROR_GET);
                break;
            default:
                RETURN_ERROR(ERROR_GET);
        }
    }

    /* unaligned */
    buf = global_buf;
    len = off;

    /* ff;1,01,1 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 1 || l != 1 || ret != 4+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[4])
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;02,12,'2'x258 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 2 || l != 0x0102 || ret != 6+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[6])
        RETURN_ERROR(ERROR_GET);
    if (memspn(v, '2', l) != l)
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 3,2,12 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 3 || l != 2 || ret != 2+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[2])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "12", 2))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 4444,04,1234 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 0x04040404 || l != 4 || ret != 6+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != &buf[6])
        RETURN_ERROR(ERROR_GET);
    if (memcmp(v, "1234", 4))
        RETURN_ERROR(ERROR_CMP);
    buf += ret;
    len -= ret;

    /* 5,00 */
    t = l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret <= 0)
        RETURN_ERROR(ERROR_GET);
    if (t != 5 || l != 0 || ret != 3+l)
        RETURN_ERROR(ERROR_GET);
    memcpy(&v, &tmp[1], sizeof(v));
    if (v != NULL)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    /* ff;ff;0 */
    t = 1; l = 0; tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0xFF;
    ret = libtlv_get(opt, buf, len, &t, &l, &tmp[1]);
    if (ret != 2)
        RETURN_ERROR(ERROR_GET);
    if (t != 0)
        RETURN_ERROR(ERROR_GET);
    buf += ret;
    len -= ret;

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put return */
static int test_tvlvp_putret(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = GLOBAL_LEN;

    unsigned int opt = LIBTLV_OPT_TVLVP;
    unsigned int t;
    unsigned int l;

    memset(buf, 0, len);
    memset(tmp, 0, len);

    /* size<0 => -E2BIG */
    ret = libtlv_put(opt, NULL, (size_t)-1, 0, 0, NULL);
    if (ret != -E2BIG)
        RETURN_ERROR(ERROR_RET);

    /* buf==NULL, size>0 => -EINVAL */
    ret = libtlv_put(opt, NULL, (size_t)1, 0, 0, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *t>0xFDFFFFF => -EINVAL */
    t = 0xFE00000;
    l = 0;
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* *l>0xFFFFFFF => -EINVAL */
    t = 1;
    l = (1U<<28);
    ret = libtlv_put(opt, buf, len, t, l, tmp);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* t!=0, l!=0, v==NULL => -EINVAL */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, len, t, l, NULL);
    if (ret != -EINVAL)
        RETURN_ERROR(ERROR_RET);

    /* buf==[], t==1, l==1, v!=NULL => -ENOSPC */
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, 0, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0], t==1, l==1, v!=NULL => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[0x80,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;0x80,1] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,0x80,0x80] t==1, l==1 => -EFAULT */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    t = 1;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -EFAULT)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;1,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[ff;01,01,1] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0,00] t==2, l==1 => 7 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 7 || buf[4] != 2 || buf[5] != 1 || buf[6] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;ff;0,00] t==2, l==1 => 10 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 10 || buf[7] != 2 || buf[8] != 1 || buf[9] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;0,00] t==2, l==1 => 8 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 8 || buf[5] != 2 || buf[6] != 1 || buf[7] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;ff;0,00] t==2, l==1 => 10 */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0x80;
    buf[off++] = 0;
    t = 2;
    l = 1;
    tmp[0] = 3;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 10 || buf[7] != 2 || buf[8] != 1 || buf[9] != 3)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;ff;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[01,01,1;ff;ff;0,0] t==2, l==1 => -ENOSPC */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0xff;
    buf[off++] = 0;
    buf[off++] = 0;
    t = 2;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != -ENOSPC)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;0] t==0, l==1 => 4 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 4)
        RETURN_ERROR(ERROR_RET);

    /* buf==[1,01,1;ff;0] t==0, l==1 => 5 */
    off = 0;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 0;
    l = 1;
    ret = libtlv_put(opt, buf, off, t, l, tmp);
    if (ret != 5)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[0001,01,1;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    /* PUT_ONCE: buf==[ff;0001,01,1;ff;0] t==1, l==1 => -EEXIST */
    off = 0;
    buf[off++] = 0xff;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 0x80;
    buf[off++] = 1;
    buf[off++] = 1;
    buf[off++] = 0xff;
    buf[off++] = 0;
    t = 1;
    l = 1;
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_ONCE, buf, off, t, l, tmp);
    if (ret != -EEXIST)
        RETURN_ERROR(ERROR_RET);

    assert(off < GLOBAL_LEN);
    RETURN_ERROR(0);
}

/* test tlv put output */
static int test_tvlvp_output(const char *name)
{
    int      ret;
    int      off;
    uint8_t *buf = global_buf;
    uint8_t *tmp = global_tmp;
    size_t   len = sizeof(global_buf);

    unsigned int opt = LIBTLV_OPT_TVLVP;
    unsigned int t, l, p = 0;

    memset(buf, 0, len);
    memset(tmp, 0, len);
    off = 0;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

    /* t=1, l=1, v=1 */
    t = 1;
    tmp[off+0] = t;
    l = 1;
    tmp[off+1] = 1;
    tmp[off+2] = 1;
    ret = libtlv_put(opt, buf, len, t, l, &tmp[off+2]);
    if (ret != 2 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret;

    /* ff */
    tmp[off++] = *buf++ = 0xff;
    --len;

    /* t=12, l=13, v='2'x259 */
    t = 0x0102;
    tmp[off+0] = 0x80;
    tmp[off+1] = 0x80;
    tmp[off+2] = 0x80 | (t >> 7);
    tmp[off+3] = 0x7f & t;
    l = 0x0103;
    tmp[off+4] = 0x80;
    tmp[off+5] = 0x80;
    tmp[off+6] = 0x80 | (l >> 7);
    tmp[off+7] = 0x7f & l;
    memset(&tmp[off+8], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_INIT, buf, len, t, l, &tmp[off+8]);
    if (ret != 8)
        RETURN_ERROR(ERROR_PUT);
    memset(&buf[8], '2', l);
    ret = libtlv_put(opt | LIBTLV_OPT_PUT_FINI, buf, len, t, l, &tmp[off+8]);
    if (ret != 8)
        RETURN_ERROR(ERROR_PUT);
    ret += l;
    buf += ret;
    len -= ret;
    off += ret;

#if     ENABLE_LIBTLV_ALIGN_SUPPORT
    /* align t to 32 */
    tmp[off++] = 0xff; // 272
    tmp[off++] = 0xff; // 273
    tmp[off++] = 0xff; // 274
    tmp[off++] = 0xff; // 275
    tmp[off++] = 0xff; // 276
    tmp[off++] = 0xff; // 277
    tmp[off++] = 0xff; // 278
    tmp[off++] = 0xff; // 279
    tmp[off++] = 0xff; // 280
    tmp[off++] = 0xff; // 281
    tmp[off++] = 0xff; // 282
    tmp[off++] = 0xff; // 283
    tmp[off++] = 0xff; // 284
    p = 13;
#else /*ENABLE_LIBTLV_ALIGN_SUPPORT*/
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
    tmp[off++] = *buf++ = 0xff;
    --len;
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

    /* t=13, l=4, v=123\0 */
    t = 0x0103;
    tmp[off+0] = 0x80 | (t >> 7);
    tmp[off+1] = 0x7f & t;
    l = 4;
    tmp[off+2] = l;
    memcpy(&tmp[off+3], "123", 4);
    ret = libtlv_put(opt | LIBTLV_OPT_ALIGNV | LIBTLV_OPT_ALN32B,
                     buf, len, t, l, &tmp[off+3]);
    if (ret != p + 3 + l)
        RETURN_ERROR(ERROR_PUT);
    buf += ret;
    len -= ret;
    off += ret - p;

    /* append: t=4, l=5, v=12345 */
    t = 4;
    tmp[off+0] = t;
    l = 5;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "12345", 5);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    /* append+dup: t=4, l=6, v=123456 */
    t = 4;
    tmp[off+0] = t;
    l = 6;
    tmp[off+1] = l;
    memcpy(&tmp[off+2], "123456", 6);
    ret = libtlv_put(opt, global_buf, GLOBAL_LEN, t, l, &tmp[off+2]);
    if (ret != off + 2 + l)
        RETURN_ERROR(ERROR_PUT);
    ret -= off;
    buf += ret;
    len -= ret;
    off += ret;

    assert(off < GLOBAL_LEN);
    if (memcmp(global_buf, global_tmp, off))
        RETURN_ERROR(ERROR_CMP);

    RETURN_ERROR(0);
}

/*
 * END tvlvp: t=v l=v with padding
 */
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/

int main(int argc, char *argv[])
{
    struct testcase
    {
        const char *name;
        int (*func)(const char *);
    } testcases[] =
    {
        { "",                NULL                 },
        { "t1l1n getret ",   test_t1l1n_getret    },
        { "t1l1n input  ",   test_t1l1n_input     },
        { "t1l1n getnext",   test_t1l1n_getnext   },
        { "t1l1n putret ",   test_t1l1n_putret    },
        { "t1l1n output ",   test_t1l1n_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "t1l1p getret ",   test_t1l1p_getret    },
        { "t1l1p input  ",   test_t1l1p_input     },
        { "t1l1p getnext",   test_t1l1p_getnext   },
        { "t1l1p putret ",   test_t1l1p_putret    },
        { "t1l1p output ",   test_t1l1p_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

        { "t2l1n getret ",   test_t2l1n_getret    },
        { "t2l1n input  ",   test_t2l1n_input     },
        { "t2l1n getnext",   test_t2l1n_getnext   },
        { "t2l1n putret ",   test_t2l1n_putret    },
        { "t2l1n output ",   test_t2l1n_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "t2l1p getret ",   test_t2l1p_getret    },
        { "t2l1p input  ",   test_t2l1p_input     },
        { "t2l1p getnext",   test_t2l1p_getnext   },
        { "t2l1p putret ",   test_t2l1p_putret    },
        { "t2l1p output ",   test_t2l1p_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

        { "t1l2n getret ",   test_t1l2n_getret    },
        { "t1l2n input  ",   test_t1l2n_input     },
        { "t1l2n getnext",   test_t1l2n_getnext   },
        { "t1l2n putret ",   test_t1l2n_putret    },
        { "t1l2n output ",   test_t1l2n_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "t1l2p getret ",   test_t1l2p_getret    },
        { "t1l2p input  ",   test_t1l2p_input     },
        { "t1l2p getnext",   test_t1l2p_getnext   },
        { "t1l2p putret ",   test_t1l2p_putret    },
        { "t1l2p output ",   test_t1l2p_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

        { "t2l2n getret ",   test_t2l2n_getret    },
        { "t2l2n input  ",   test_t2l2n_input     },
        { "t2l2n getnext",   test_t2l2n_getnext   },
        { "t2l2n putret ",   test_t2l2n_putret    },
        { "t2l2n output ",   test_t2l2n_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "t2l2p getret ",   test_t2l2p_getret    },
        { "t2l2p input  ",   test_t2l2p_input     },
        { "t2l2p getnext",   test_t2l2p_getnext   },
        { "t2l2p putret ",   test_t2l2p_putret    },
        { "t2l2p output ",   test_t2l2p_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

#if     ENABLE_LIBTLV_VARLEN_SUPPORT
        { "t1lvn getret ",   test_t1lvn_getret    },
        { "t1lvn input  ",   test_t1lvn_input     },
        { "t1lvn getnext",   test_t1lvn_getnext   },
        { "t1lvn putret ",   test_t1lvn_putret    },
        { "t1lvn output ",   test_t1lvn_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "t1lvp getret ",   test_t1lvp_getret    },
        { "t1lvp input  ",   test_t1lvp_input     },
        { "t1lvp getnext",   test_t1lvp_getnext   },
        { "t1lvp putret ",   test_t1lvp_putret    },
        { "t1lvp output ",   test_t1lvp_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

        { "t2lvn getret ",   test_t2lvn_getret    },
        { "t2lvn input  ",   test_t2lvn_input     },
        { "t2lvn getnext",   test_t2lvn_getnext   },
        { "t2lvn putret ",   test_t2lvn_putret    },
        { "t2lvn output ",   test_t2lvn_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "t2lvp getret ",   test_t2lvp_getret    },
        { "t2lvp input  ",   test_t2lvp_input     },
        { "t2lvp getnext",   test_t2lvp_getnext   },
        { "t2lvp putret ",   test_t2lvp_putret    },
        { "t2lvp output ",   test_t2lvp_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

        { "tvlvn getret ",   test_tvlvn_getret    },
        { "tvlvn input  ",   test_tvlvn_input     },
        { "tvlvn getnext",   test_tvlvn_getnext   },
        { "tvlvn putret ",   test_tvlvn_putret    },
        { "tvlvn output ",   test_tvlvn_output    },
        { "",                NULL                 },

#if     ENABLE_LIBTLV_PADDING_SUPPORT
        { "tvlvp getret ",   test_tvlvp_getret    },
        { "tvlvp input  ",   test_tvlvp_input     },
        { "tvlvp getnext",   test_tvlvp_getnext   },
        { "tvlvp putret ",   test_tvlvp_putret    },
        { "tvlvp output ",   test_tvlvp_output    },
        { "",                NULL                 },
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/

        { NULL, NULL },
    };
    struct testcase *test;
    int w_num  = 5;
    int w_name = 20;
    int num_test = 0;
    int num_pass = 0;
    int num_fail = 0;

    printf("%*s %*s : %s\n", w_num, "Num", w_name, "Name", "Result");
    for (test = &testcases[0]; test->name; ++test)
    {
        int ret;
        if (!test->name[0])
        {
            printf("\n");
            continue;
        }
        if (!test->func)
        {
            break;
        }
        ret = test->func(test->name);
        printf("%*d %*s : %s (%d @ %d)\n", w_num, num_test, w_name, test->name, ret ? "FAIL" : "PASS", ret, ERROR_LINE);
        ++num_test;
        if (ret)
            ++num_fail;
        else
            ++num_pass;
    }
    printf("%*s %*s : %*d / %d\n", w_num, "", w_name, "PASS", w_num, num_pass, num_test);
    printf("%*s %*s : %*d / %d\n", w_num, "", w_name, "FAIL", w_num, num_fail, num_test);

    return (num_fail != 0);
}

/*
 * Local Variables:
 *   c-file-style: "stroustrup"
 *   indent-tabs-mode: nil
 * End:
 *
 * vim: set ai cindent et sta sw=4:
 */
