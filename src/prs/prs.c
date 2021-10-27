#include <stdint.h>
#include <stdio.h>
#include <memory.h>

////////////////////////////////////////////////////////////////////////////////

typedef struct {
    uint8_t bitpos;
    uint8_t* controlbyteptr;
    uint8_t* srcptr_orig;
    uint8_t* dstptr_orig;
    uint8_t* srcptr;
    uint8_t* dstptr;
} PRS_COMPRESSOR;

void prs_put_control_bit(PRS_COMPRESSOR* pc,uint8_t bit)
{
    *pc->controlbyteptr = *pc->controlbyteptr >> 1;
    *pc->controlbyteptr |= ((!!bit) << 7);
    pc->bitpos++;
    if (pc->bitpos >= 8)
    {
        pc->bitpos = 0;
        pc->controlbyteptr = pc->dstptr;
        pc->dstptr++;
    }
}

void prs_put_control_bit_nosave(PRS_COMPRESSOR* pc,uint8_t bit)
{
    *pc->controlbyteptr = *pc->controlbyteptr >> 1;
    *pc->controlbyteptr |= ((!!bit) << 7);
    pc->bitpos++;
}

void prs_put_control_save(PRS_COMPRESSOR* pc)
{
    if (pc->bitpos >= 8)
    {
        pc->bitpos = 0;
        pc->controlbyteptr = pc->dstptr;
        pc->dstptr++;
    }
}

void prs_put_static_data(PRS_COMPRESSOR* pc,uint8_t data)
{
    *pc->dstptr = data;
    pc->dstptr++;
}

uint8_t prs_get_static_data(PRS_COMPRESSOR* pc)
{
    uint8_t data = *pc->srcptr;
    pc->srcptr++;
    return data;
}

////////////////////////////////////////////////////////////////////////////////

void prs_init(PRS_COMPRESSOR* pc,void* src,void* dst)
{
    pc->bitpos = 0;
    pc->srcptr = (uint8_t*)src;
    pc->srcptr_orig = (uint8_t*)src;
    pc->dstptr = (uint8_t*)dst;
    pc->dstptr_orig = (uint8_t*)dst;
    pc->controlbyteptr = pc->dstptr;
    pc->dstptr++;
}

void prs_finish(PRS_COMPRESSOR* pc)
{
    prs_put_control_bit(pc,0);
    prs_put_control_bit(pc,1);
    if (pc->bitpos != 0)
    {
        *pc->controlbyteptr = ((*pc->controlbyteptr << pc->bitpos) >> 8);
    }
    prs_put_static_data(pc,0);
    prs_put_static_data(pc,0);
}

void prs_rawbyte(PRS_COMPRESSOR* pc)
{
    prs_put_control_bit_nosave(pc,1);
    prs_put_static_data(pc,prs_get_static_data(pc));
    prs_put_control_save(pc);
}

void prs_shortcopy(PRS_COMPRESSOR* pc,int offset,uint8_t size)
{
    size -= 2;
    prs_put_control_bit(pc,0);
    prs_put_control_bit(pc,0);
    prs_put_control_bit(pc,(size >> 1) & 1);
    prs_put_control_bit_nosave(pc,size & 1);
    prs_put_static_data(pc,offset & 0xFF);
    prs_put_control_save(pc);
}

void prs_longcopy(PRS_COMPRESSOR* pc,int offset,uint8_t size)
{
    if (size <= 9)
    {
        prs_put_control_bit(pc,0);
        prs_put_control_bit_nosave(pc,1);
        prs_put_static_data(pc,((offset << 3) & 0xF8) | ((size - 2) & 0x07));
        prs_put_static_data(pc,(offset >> 5) & 0xFF);
        prs_put_control_save(pc);
    } else {
        prs_put_control_bit(pc,0);
        prs_put_control_bit_nosave(pc,1);
        prs_put_static_data(pc,(offset << 3) & 0xF8);
        prs_put_static_data(pc,(offset >> 5) & 0xFF);
        prs_put_static_data(pc,size - 1);
        prs_put_control_save(pc);
    }
}

void prs_copy(PRS_COMPRESSOR* pc,int offset,uint8_t size)
{
    if ((offset > -0x100) && (size <= 5))
    {
        prs_shortcopy(pc,offset,size);
    } else {
        prs_longcopy(pc,offset,size);
    }
    pc->srcptr += size;
}

////////////////////////////////////////////////////////////////////////////////

uint32_t prs_compress(void* source,void* dest,uint32_t size)
{
    PRS_COMPRESSOR pc;
    int x,y; // int z;
    uint32_t xsize;
    int lsoffset,lssize;

    if (size > 2147483648) // keep within signed range
    {
  printf ("prs_compress failure\n");
      memcpy (dest,source,size);
  return size;
    }
    prs_init(&pc,source,dest);
    for (x = 0; x < (int) size; x++)
    {
        lsoffset = lssize = xsize = 0;
        for (y = x - 3; (y > 0) && (y > (x - 0x1FF0)) && (xsize < 255); y--)
        {
            xsize = 3;
            if (!memcmp((void*)((intptr_t)source + y),(void*)((intptr_t)source + x),xsize))
            {
                do xsize++;
                while (!memcmp((void*)((intptr_t)source + y),
                               (void*)((intptr_t)source + x),
                               xsize) &&
                       (xsize < 256) &&
                       ((y + (int)xsize) < x) &&
                       ((x + xsize) <= (uint32_t)size)
                );
                xsize--;
                if ((int)xsize > lssize)
                {
                    lsoffset = -(x - y);
                    lssize = xsize;
                }
            }
        }
        if (lssize == 0)
        {
            prs_rawbyte(&pc);
        } else {
            prs_copy(&pc,lsoffset,lssize);
            x += (lssize - 1);
        }
    }
    prs_finish(&pc);
    return pc.dstptr - pc.dstptr_orig;
}

////////////////////////////////////////////////////////////////////////////////

uint32_t prs_decompress(void* source,void* dest) // 800F7CB0 through 800F7DE4 in mem
{
    intptr_t r3,r5; // uint32_t r0,r6,r9; // 6 unnamed registers
    intptr_t bitpos = 9; // 4 named registers
    uint8_t* sourceptr = (uint8_t*)source;
    uint8_t* destptr = (uint8_t*)dest;
    uint8_t* destptr_orig = (uint8_t*)dest;
    uint8_t currentbyte;
    int flag;
    int offset;
    uint32_t x,t; // 2 placed variables

    currentbyte = sourceptr[0];
    sourceptr++;
    for (;;)
    {
        bitpos--;
        if (bitpos == 0)
        {
            currentbyte = sourceptr[0];
            bitpos = 8;
            sourceptr++;
        }
        flag = currentbyte & 1;
        currentbyte = currentbyte >> 1;
        if (flag)
        {
            destptr[0] = sourceptr[0];
            sourceptr++;
            destptr++;
            continue;
        }
        bitpos--;
        if (bitpos == 0)
        {
            currentbyte = sourceptr[0];
            bitpos = 8;
            sourceptr++;
        }
        flag = currentbyte & 1;
        currentbyte = currentbyte >> 1;
        if (flag)
        {
            r3 = sourceptr[0] & 0xFF;
            offset = ((sourceptr[1] & 0xFF) << 8) | r3;
            sourceptr += 2;
            if (offset == 0) return (intptr_t)(destptr - destptr_orig);
            r3 = r3 & 0x00000007;
            r5 = (offset >> 3) | (~0x1FFF);
            if (r3 == 0)
            {
                flag = 0;
                r3 = sourceptr[0] & 0xFF;
                sourceptr++;
                r3++;
            } else r3 += 2;
            r5 += (intptr_t)destptr;
        } else {
            r3 = 0;
            for (x = 0; x < 2; x++)
            {
                bitpos--;
                if (bitpos == 0)
                {
                    currentbyte = sourceptr[0];
                    bitpos = 8;
                    sourceptr++;
                }
                flag = currentbyte & 1;
                currentbyte = currentbyte >> 1;
                offset = r3 << 1;
                r3 = offset | flag;
            }
            offset = sourceptr[0] | ~(0xFF);
            r3 += 2;
            sourceptr++;
            r5 = offset + (intptr_t)destptr;
        }
        if (r3 == 0) continue;
        t = r3;
        for (x = 0; x < t; x++)
        {
            destptr[0] = *(uint8_t*)r5;
            r5++;
            r3++;
            destptr++;
        }
    }
}

uint32_t prs_decompress_size(void* source)
{
    intptr_t r3,r5; // uint32_t r0,r6,r9; // 6 unnamed registers
    intptr_t bitpos = 9; // 4 named registers
    uint8_t* sourceptr = (uint8_t*)source;
    uint8_t* destptr = 0;
    uint8_t* destptr_orig = 0;
    uint8_t currentbyte;
    int flag;
    int offset;
    uint32_t x,t; // 2 placed variables

    currentbyte = sourceptr[0];
    sourceptr++;
    for (;;)
    {
        bitpos--;
        if (bitpos == 0)
        {
            bitpos = 8;
            sourceptr++;
        }
        flag = currentbyte & 1;
        currentbyte = currentbyte >> 1;
        if (flag)
        {
            sourceptr++;
            destptr++;
            continue;
        }
        bitpos--;
        if (bitpos == 0)
        {
            bitpos = 8;
            sourceptr++;
        }
        flag = currentbyte & 1;
        currentbyte = currentbyte >> 1;
        if (flag)
        {
            r3 = sourceptr[0];
            offset = (sourceptr[1] << 8) | r3;
            sourceptr += 2;
            if (offset == 0) return (intptr_t)(destptr - destptr_orig);
            r3 = r3 & 0x00000007;
            r5 = (offset >> 3) | ~(0x1FFF);
            if (r3 == 0)
            {
                r3 = sourceptr[0];
                sourceptr++;
                r3++;
            } else r3 += 2;
            r5 += (intptr_t)destptr;
        } else {
            r3 = 0;
            for (x = 0; x < 2; x++)
            {
                bitpos--;
                if (bitpos == 0)
                {
                    bitpos = 8;
                    sourceptr++;
                }
                flag = currentbyte & 1;
                currentbyte = currentbyte >> 1;
                offset = r3 << 1;
                r3 = offset | flag;
            }
            offset = sourceptr[0] | ~(0xFF);
            r3 += 2;
            sourceptr++;
            r5 = offset + (intptr_t)destptr;
        }
        if (r3 == 0) continue;
        t = r3;
        for (x = 0; x < t; x++)
        {
            r5++;
            r3++;
            destptr++;
        }
    }
}

