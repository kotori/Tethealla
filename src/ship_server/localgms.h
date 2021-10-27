//! ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*!

Header for local GMs on Tethealla ships.

Written by Jon Wayne Parrott 8/18/08

Modified by Sodaboy for compatibility under
VC++ 2008 8/21/2008

This source is under no copyright.

*/
//! ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


typedef struct st_localgm
{
    uint32_t guildcard;
    int32_t level;
} LOCALGM;

LOCALGM localgms[100];
int32_t localgmcount = -1;
int32_t localgmrights[11];

int32_t readLocalGMFile()
{
    FILE* gmfile;
    char inistring[512];
    int32_t i;

  printf( "Loading Local GMs and permissions..\n" );

    gmfile = fopen("localgms.ini", "r");

    if ( gmfile != NULL )
    {
        printf( "Local GM File Loaded, Parsing...\n" );

        if(!fgets(inistring, 512, gmfile)) {
          printf ("Failed to read...\n");
          exit(1);
        }

        while ( !feof(gmfile) )
        {
            if ( inistring[0] != '#' && inistring[0] != ';' )
            {
                //! GC# and privledge level of local gms
                if (strstr(inistring,"[localgms]") != NULL)
                {
                    while ( fgets(inistring, 512, gmfile) )
                    {
                        if ( inistring[0] != '#' && inistring[0] != ';' && inistring[0] != '[' )
                        {

                            localgmcount += 1;

                            localgms[localgmcount].guildcard = atoi(strtok(inistring,","));
                            localgms[localgmcount].level = atoi(strtok(NULL,","));

              printf ("Added GM # %u with rights level %u\n", localgms[localgmcount].guildcard, localgms[localgmcount].level);

                        }
                        if ( inistring[0] == '[' )
                        {
                            break;
                        }
                    }
                }
                else
                //! Rights
                if (strstr(inistring,"[gmrights]") != NULL)
                {
                    while ( fgets(inistring, 512, gmfile) )
                    {
                        if ( inistring[0] != '#' && inistring[0] != ';' && inistring[0] != '[' )
                        {

                            int32_t index = atoi(strtok(inistring,","));

                            localgmrights[index] = atoi(strtok(NULL,","));

                        }
                        if ( inistring[0] == '[' )
                        {
                            break;
                        }
                    }
                }

                else
                {
                    if(!fgets(inistring, 512, gmfile))
                    {
                      printf ("Failed to read...\n");
                      exit(1);
                    }
                }
            }
            else
            {
                if(!fgets(inistring, 512, gmfile))
                {
                  printf ("Failed to read...\n");
                  exit(1);
                }
            }
        }

        for(i=0;i<10;i++)
        {
      if ( localgmrights[i] )
        printf(" Index %i: Permission %i\n", i, localgmrights[i]);
        }

        fclose(gmfile);
        return 1;

    }
    else
    {
        printf( "Failed to load localgms.ini!" );
        return 0;
    }

}

int32_t getbit( int32_t value, int32_t bit)
{
    int32_t mask = 1<<bit;

    if((value&mask)>0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int32_t playerHasRights( uint32_t guildcard, int32_t command)
{
    int32_t i;
    int32_t rights = 0;

    //printf("Checking player %i's permission",guildcard);
    for(i = 0; i <= localgmcount; i++)
    {
        if( localgms[i].guildcard == guildcard )
        {
            rights = localgmrights[localgms[i].level];
            //printf("player has rights %i\n", rights);
        }
    }

    if(getbit(rights,command))
    {
        //printf("player authorized\n");
        return 1;
    }
    else
    {
        return 0;
    }
}

int32_t isLocalGM( uint32_t guildcard )
{
    int32_t i;
    for(i = 0; i <= localgmcount; i++)
    {
        if( localgms[i].guildcard == guildcard )
        {
            return 1;
        }
    }
    return 0;
}
