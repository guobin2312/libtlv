#ifndef __LIBTLV_H
#define __LIBTLV_H

/*
 * simple tlv: t=0 for end, t=0xff for padding
 */

/* default configurations */
#define CONFIG_LIBTLV_VARLEN_SUPPORT    1
#define CONFIG_LIBTLV_PADDING_SUPPORT   1
#define CONFIG_LIBTLV_ALIGN_SUPPORT     1

#if defined(CONFIG_LIBTLV_ALIGN_SUPPORT) && !defined(CONFIG_LIBTLV_PADDING_SUPPORT)
#error CONFIG_LIBTLV_ALIGN_SUPPORT depends on CONFIG_LIBTLV_PADDING_SUPPORT
#endif

/* config (ifdef) -> enable (if 0/1) */
#ifndef ENABLE_LIBTLV_VARLEN_SUPPORT
#ifdef  CONFIG_LIBTLV_VARLEN_SUPPORT
#define ENABLE_LIBTLV_VARLEN_SUPPORT    1
#else
#define ENABLE_LIBTLV_VARLEN_SUPPORT    0
#endif
#endif/*ENABLE_LIBTLV_VARLEN_SUPPORT*/

#ifndef ENABLE_LIBTLV_PADDING_SUPPORT
#ifdef  CONFIG_LIBTLV_PADDING_SUPPORT
#define ENABLE_LIBTLV_PADDING_SUPPORT   1
#else
#define ENABLE_LIBTLV_PADDING_SUPPORT   0
#endif
#endif/*ENABLE_LIBTLV_PADDING_SUPPORT*/

#ifndef ENABLE_LIBTLV_ALIGN_SUPPORT
#ifdef  CONFIG_LIBTLV_ALIGN_SUPPORT
#define ENABLE_LIBTLV_ALIGN_SUPPORT     1
#else
#define ENABLE_LIBTLV_ALIGN_SUPPORT     0
#endif
#endif/*ENABLE_LIBTLV_ALIGN_SUPPORT*/

#if     ENABLE_LIBTLV_ALIGN_SUPPORT && !ENABLE_LIBTLV_PADDING_SUPPORT
#error ENABLE_LIBTLV_ALIGN_SUPPORT depends on ENABLE_LIBTLV_PADDING_SUPPORT
#endif

#define LIBTLV_OPT_TSZMASK        0x00000003U /* type size mask        */
#define LIBTLV_OPT_T2BYTES        0x00000001U /* type has two bytes    */
#define LIBTLV_OPT_T4BVARL        0x00000002U /* type as VLQ 4 bytes   */
#define LIBTLV_OPT_LSZMASK        0x00000030U /* length size mask      */
#define LIBTLV_OPT_L2BYTES        0x00000010U /* length has two bytes  */
#define LIBTLV_OPT_L4BVARL        0x00000020U /* length as VLQ 4 bytes */
#define LIBTLV_OPT_PADDING        0x00000400U /* padding (FF) allowed  */
#define LIBTLV_OPT_ALIGNT         0x00000500U /* align t + padding     */
#define LIBTLV_OPT_ALIGNL         0x00000600U /* align l + padding     */
#define LIBTLV_OPT_ALIGNV         0x00000700U /* align v + padding     */
#define LIBTLV_OPT_ALNSEL         0x00000700U /* align select mask     */
#define LIBTLV_OPT_ALNCNT         0x00007000U /* align count mask      */
#define LIBTLV_OPT_ALN2B          0x00001000U /* align to 2 bytes      */
#define LIBTLV_OPT_ALN4B          0x00002000U /* align to 4 bytes      */
#define LIBTLV_OPT_ALN8B          0x00003000U /* align to 8 bytes      */
#define LIBTLV_OPT_ALN16B         0x00004000U /* align to 16 bytes     */
#define LIBTLV_OPT_ALN32B         0x00005000U /* align to 32 bytes     */
#define LIBTLV_OPT_ALN64B         0x00006000U /* align to 64 bytes     */
#define LIBTLV_OPT_ALN128B        0x00007000U /* align to 128 bytes    */

#define LIBTLV_OPT_GET_LAST       0x01000000U /* get last occurred */
#define LIBTLV_OPT_PUT_ONCE       0x02000000U /* put only one copy */

#define LIBTLV_OPT_T1L1N          0
#define LIBTLV_OPT_T1L1P          (LIBTLV_OPT_PADDING)
#define LIBTLV_OPT_T2L1N          (LIBTLV_OPT_T2BYTES)
#define LIBTLV_OPT_T2L1P          (LIBTLV_OPT_T2BYTES | LIBTLV_OPT_PADDING)
#define LIBTLV_OPT_T1L2N          (LIBTLV_OPT_L2BYTES)
#define LIBTLV_OPT_T1L2P          (LIBTLV_OPT_L2BYTES | LIBTLV_OPT_PADDING)
#define LIBTLV_OPT_T2L2N          (LIBTLV_OPT_T2BYTES | LIBTLV_OPT_L2BYTES)
#define LIBTLV_OPT_T2L2P          (LIBTLV_OPT_T2BYTES | LIBTLV_OPT_L2BYTES | LIBTLV_OPT_PADDING)
#define LIBTLV_OPT_T1LVN          (LIBTLV_OPT_L4BVARL)
#define LIBTLV_OPT_T1LVP          (LIBTLV_OPT_L4BVARL | LIBTLV_OPT_PADDING)
#define LIBTLV_OPT_T2LVN          (LIBTLV_OPT_T2BYTES | LIBTLV_OPT_L4BVARL)
#define LIBTLV_OPT_T2LVP          (LIBTLV_OPT_T2BYTES | LIBTLV_OPT_L4BVARL | LIBTLV_OPT_PADDING)
#define LIBTLV_OPT_TVLVN          (LIBTLV_OPT_T4BVARL | LIBTLV_OPT_L4BVARL)
#define LIBTLV_OPT_TVLVP          (LIBTLV_OPT_T4BVARL | LIBTLV_OPT_L4BVARL | LIBTLV_OPT_PADDING)

#if     ENABLE_LIBTLV_VARLEN_SUPPORT && ENABLE_LIBTLV_PADDING_SUPPORT
#define LIBTLV_OPT_DEFAULT        LIBTLV_OPT_TVLVP
#elif   ENABLE_LIBTLV_VARLEN_SUPPORT
#define LIBTLV_OPT_DEFAULT        LIBTLV_OPT_TVLVN
#elif   ENABLE_LIBTLV_PADDING_SUPPORT
#define LIBTLV_OPT_DEFAULT        LIBTLV_OPT_T1L1P
#else
#define LIBTLV_OPT_DEFAULT        LIBTLV_OPT_T1L1N
#endif

int libtlv_get(unsigned int opt, void *buf, size_t size, unsigned int *t, unsigned int *l, void *v);
int libtlv_put(unsigned int opt, void *buf, size_t size, unsigned int  t, unsigned int  l, void *v);

#endif/*__LIBTLV_H*/

/*
 * Local Variables:
 *   c-file-style: "stroustrup"
 *   indent-tabs-mode: nil
 * End:
 *
 * vim: set ai cindent et sta sw=4:
 */
