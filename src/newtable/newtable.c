/* random number functions */

#include  <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

typedef struct st_pcrys
{
  uint32_t tbl[18];
} PCRYS;

int main()
{
  uint32_t value;
  FILE* fp;
  FILE* bp;
  uint32_t ch;

  srand (time (0));

  fp = fopen ("bbtable.h","w");
  bp = fopen ("bbtable.bin", "wb");
  fprintf (fp, "\n\nstatic const uint32_t bbtable[18+1024] =\n{\n");
  for (ch=0;ch<1024+18;ch++)
  {
    value = rand();
    fprintf (fp, "0x%08x,\n", value );
    fwrite (&value, 1, 4, bp);
  }
  fprintf (fp, "};\n");
  fclose (fp);

  return 0;
}
