# libtlv

Simple tlv library supporting variable length encoding, padding, alignment and etc.

Read (get) and write (put) functions operate on tlv buffer (empty or not) of a given size with 0 as end/empty, and 0xff as padding.

## Reading or get

````C
int libtlv_get(unsigned int opt, void *buf, size_t size, unsigned int *t, unsigned int *l, void *v);
````

## Writing or put

````C
int libtlv_put(unsigned int opt, void *buf, size_t size, unsigned int  t, unsigned int  l, void *v);
````

## Variable encoding

## Padding and alignment

## Recursive tlv
