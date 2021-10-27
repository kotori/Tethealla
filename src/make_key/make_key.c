#include "TetheallaConfig.h"
#include  <stdint.h>
#include  <stdio.h>
#include  <stdlib.h>
#include  <string.h>
#include  <time.h>
#include  <math.h>

#ifdef NO_SQL
#define SHIP_COMPILED_MAX_CONNECTIONS 50

typedef struct st_ship_data {
  uint8_t rc4key[128];
  uint32_t idx;
} L_SHIP_DATA;

uint32_t num_shipkeys = 0;
uint32_t ds;

L_SHIP_DATA *ship_data[SHIP_COMPILED_MAX_CONNECTIONS];

#else
#include  <mysql/mysql.h>
#endif

#ifdef NO_SQL

void UpdateDataFile ( const char* filename, uint32_t count, void* data, uint32_t record_size, int32_t new_record )
{
  FILE* fp;
  uint32_t fs;

  fp = fopen (filename, "r+b");
  if (fp)
  {
    fseek (fp, 0, SEEK_END);
    fs = ftell (fp);
    if ((count * record_size) <= fs)
    {
      fseek (fp, count * record_size, SEEK_SET);
      fwrite (data, 1, record_size, fp);
    }
    else
      printf ("Could not seek to record for updating in %s\n", filename);
    fclose (fp);
  }
  else
  {
    fp = fopen (filename, "wb");
    if (fp)
    {
      fwrite (data, 1, record_size, fp); // Has to be the first record...
      fclose (fp);
    }
    else
      printf ("Could not open %s for writing!\n", filename);
  }
}

void LoadDataFile ( const char* filename, unsigned* count, void** data, uint32_t record_size )
{
  FILE* fp;
  uint32_t ch;

  printf ("Loading \"%s\" ... ", filename);
  fp = fopen (filename, "rb");
  if (fp)
  {
    fseek (fp, 0, SEEK_END);
    *count = ftell (fp) / record_size;
    fseek (fp, 0, SEEK_SET);
    for (ch=0;ch<*count;ch++)
    {
      data[ch] = malloc (record_size);
      if (!data[ch])
      {
        printf ("Out of memory!");
        exit (1);
      }
      fread (data[ch], 1, record_size, fp);
    }
    fclose (fp);
  }
  printf ("done!\n");
}

#endif

int32_t main()
{
  uint32_t ch;
  uint32_t ship_index;
  char ship_key[128];
  char ship_string[255];
  FILE* fp;
#ifdef NO_SQL
  uint32_t highid = 0;
#else
  MYSQL * myData;
#endif
  char myQuery[512] = {0};
  char mySQL_Host[255] = {0};
  char mySQL_Username[255] = {0};
  char mySQL_Password[255] = {0};
  char mySQL_Database[255] = {0};
  uint32_t mySQL_Port;
  int32_t config_index = 0;
  char config_data[255];


  srand (time (0));

  if ( ( fp = fopen ("tethealla.ini", "r" ) ) == NULL )
  {
    printf ("The configuration file tethealla.ini appears to be missing.\n");
    return 1;
  }
  else
  {
    while (fgets (&config_data[0], 255, fp) != NULL)
    {
      strtok(config_data, "\r\n");
      if (config_data[0] != 0x23)
      {
        if (config_index < 0x04)
        {
          ch = strlen (&config_data[0]);
          if (config_data[ch-1] == 0x0A)
            config_data[ch--]  = 0x00;
          config_data[ch] = 0;
        }
        switch (config_index)
        {
        case 0x00:
          // MySQL Host
          memcpy (&mySQL_Host[0], &config_data[0], ch+1);
          break;
        case 0x01:
          // MySQL Username
          memcpy (&mySQL_Username[0], &config_data[0], ch+1);
          break;
        case 0x02:
          // MySQL Password
          memcpy (&mySQL_Password[0], &config_data[0], ch+1);
          break;
        case 0x03:
          // MySQL Database
          memcpy (&mySQL_Database[0], &config_data[0], ch+1);
          break;
        case 0x04:
          // MySQL Port
          mySQL_Port = atoi (&config_data[0]);
          break;
        default:
          break;
        }
        config_index++;
      }
    }
    fclose (fp);
  }

  if (config_index < 5)
  {
    printf ("tethealla.ini seems to be corrupted.\n");
    return 1;
  }

#ifdef NO_SQL

  LoadDataFile ("shipkey.dat", &num_shipkeys, &ship_data[0], sizeof(L_SHIP_DATA));

#else

  if ( (myData = mysql_init((MYSQL*) 0)) &&
    mysql_real_connect( myData, &mySQL_Host[0], &mySQL_Username[0], &mySQL_Password[0], NULL, mySQL_Port,
    NULL, 0 ) )
  {
    if ( mysql_select_db( myData, &mySQL_Database[0] ) < 0 ) {
      printf( "Can't select the %s database !\n", mySQL_Database ) ;
      mysql_close( myData ) ;
      return 2 ;
    }
  }
  else
  {
    printf( "Can't connect to the mysql server (%s) on port %d !\nmysql_error = %s\n",
      mySQL_Host, mySQL_Port, mysql_error(myData) ) ;

    mysql_close( myData ) ;
    return 1 ;
  }

#endif

  printf ("Tethealla Server Ship Key Generator\n");
  printf ("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");

  for (ch=0;ch<128;ch++)
    ship_key[ch] = rand() % 256;

#ifdef NO_SQL

  for (ds=0;ds<num_shipkeys;ds++)
  {
    if (highid < ship_data[ds]->idx)
      highid = ship_data[ds]->idx;
  }

  highid++;

  ship_data[num_shipkeys] = malloc ( sizeof ( L_SHIP_DATA ) );
  ship_data[num_shipkeys]->idx = ship_index = highid;
  memcpy (&ship_data[num_shipkeys]->rc4key[0], &ship_key[0], 128);

  UpdateDataFile ("shipkey.dat", num_shipkeys, ship_data[num_shipkeys], sizeof ( L_SHIP_DATA ), 1 );

  printf ("Key generated and successfully added to database! ID: %u\n", ship_index);

#else

  mysql_real_escape_string ( myData, &ship_string[0], &ship_key[0], 0x80 );

  sprintf (myQuery, "INSERT into ship_data (rc4key) VALUES ('%s')", ship_string );
  if ( ! mysql_query ( myData, myQuery ) )
  {
    ship_index = (unsigned) mysql_insert_id ( myData );
    printf ("Key generated and successfully added to database! ID: %u\n", ship_index);
  }
  else
  {
    printf ("Couldn't query the MySQL server.\n");
    return 1;
  }

  mysql_close( myData ) ;

#endif

  printf ("Writing ship_key.bin... ");
  fp = fopen ("ship_key.bin", "wb");
  fwrite (&ship_index, 1, 4, fp);
  fwrite (&ship_key, 1, 128, fp);
  fclose (fp);
  printf ("OK!!!\n");
  strtok(ship_key, "\r\n");
  exit (1);
  return 0;
}
