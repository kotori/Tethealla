/************************************************************************
  Tethealla Patch Server
  Copyright (C) 2008  Terry Chatman Jr.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 3 as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
************************************************************************/

#include  <stdbool.h>
#include  <stdint.h>
#include  <stdarg.h>
#include  <stdio.h>
#include  <stdlib.h>
#include  <netdb.h>
#include  <unistd.h>
#include  <string.h>
#include  <sys/time.h>
#include  <sys/socket.h>
#include  <netinet/in.h>
#include  <arpa/inet.h>
#include  <errno.h>
#include  <linux/limits.h>
#include  <ctype.h>
#include  <time.h>
#include  <dirent.h>

// Encryption data struct
typedef struct {
    uint32_t keys[1042]; // encryption stream
    uint32_t pc_posn; // PSOPC crypt position
} CRYPT_SETUP;

uint32_t CRYPT_PC_GetNextKey(CRYPT_SETUP*);
void CRYPT_PC_MixKeys(CRYPT_SETUP*);
void CRYPT_PC_CreateKeys(CRYPT_SETUP*,uint32_t);
void CRYPT_PC_CryptData(CRYPT_SETUP*,void*,uint32_t);

#define MAX_PATCHES 4096
#define PATCH_COMPILED_MAX_CONNECTIONS 300
#define SERVER_VERSION "0.010"

#define SEND_PACKET_02 0x00
#define RECEIVE_PACKET_02 0x01
#define RECEIVE_PACKET_10 0x02
#define SEND_PACKET_0B 0x03
#define MAX_SENDCHECK 0x04

//#define USEADDR_ANY
//#define DEBUG_OUTPUT
#define TCP_BUFFER_SIZE 65530

/* added stuff */

#define SOCKET_ERROR  -1

void strupr(char *temp) {

  // Convert to upper case
  char *s = temp;
  while (*s) {
    *s = toupper(*s);
    s++;
  }

}

void strlwr(char *temp) {

  // Convert to upper case
  char *s = temp;
  while (*s) {
    *s = tolower(*s);
    s++;
  }

}

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

/* functions */

void send_to_server(int sock, char* packet);
int32_t receive_from_server(int sock, char* packet);
void debug(char *fmt, ...);
void debug_perror(char * msg);
void tcp_listen (int sockfd);
int32_t tcp_accept (int sockfd, struct sockaddr *client_addr, uint32_t *addr_len );
int32_t tcp_sock_connect(char* dest_addr, int32_t port);
int32_t tcp_sock_open(struct in_addr ip, int32_t port);

/* "Welcome" Packet */

uint8_t Packet02[] = {
  0x4C, 0x00, 0x02, 0x00, 0x50, 0x61, 0x74, 0x63, 0x68, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
  0x2E, 0x20, 0x43, 0x6F, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x53, 0x6F, 0x6E, 0x69,
  0x63, 0x54, 0x65, 0x61, 0x6D, 0x2C, 0x20, 0x4C, 0x54, 0x44, 0x2E, 0x20, 0x32, 0x30, 0x30, 0x31,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x2D, 0x69, 0x06, 0x9E, 0xDC, 0xE0, 0x6F, 0xCA
};

const uint8_t Message02[] = { "Tethealla Patch" };

/* String sent to server to retrieve IP address. */

char* HTTP_REQ = "GET http://www.pioneer2.net/remote.php HTTP/1.0\r\n\r\n\r\n";

/* Populated by load_config_file(): */

uint8_t serverIP[4];
uint16_t serverPort;
int32_t override_on = 0;
uint8_t overrideIP[4];
uint16_t serverMaxConnections;
uint32_t serverNumConnections = 0;
uint32_t serverConnectionList[PATCH_COMPILED_MAX_CONNECTIONS]; // One patch, one data.

int8_t Welcome_Message[4096] = {0};
uint16_t Welcome_Message_Size = 0;
time_t servertime;
time_t sendtime;
int32_t maxbytes  = 0;

/* Client Structure */

typedef struct st_patch_data {
  uint32_t file_size;
  uint32_t checksum;
  int8_t full_file_name[PATH_MAX+48];
  int8_t file_name[48];
  int8_t folder[PATH_MAX];
  uint8_t patch_folders[128]; // Command to get to the folder this file resides in...
  uint32_t patch_folders_size;
  uint32_t patch_steps; // How many steps from the root folder this file is...
} patch_data;

typedef struct st_client_data {
  uint32_t file_size;
  uint32_t checksum;
} client_data;

typedef struct st_banana {
  int32_t patch;
  int32_t plySockfd;
  uint8_t peekbuf[8];
  uint8_t rcvbuf [TCP_BUFFER_SIZE];
  uint16_t rcvread;
  uint16_t expect;
  uint8_t decryptbuf [TCP_BUFFER_SIZE];
  uint8_t sndbuf [TCP_BUFFER_SIZE];
  uint8_t encryptbuf [TCP_BUFFER_SIZE];
  int32_t snddata,
    sndwritten;
  uint8_t packet [TCP_BUFFER_SIZE];
  uint16_t packetdata;
  uint16_t packetread;
  int32_t crypt_on;
  CRYPT_SETUP server_cipher, client_cipher;
  client_data p_data[MAX_PATCHES];
  int32_t sending_files;
  uint32_t files_to_send;
  uint32_t bytes_to_send;
  uint32_t s_data[MAX_PATCHES];
  int8_t username[17];
  uint32_t current_file;
  uint32_t cfile_index;
  uint32_t lastTick;    // The last second
  uint32_t toBytesSec;  // How many bytes per second the server sends to the client
  uint32_t fromBytesSec;  // How many bytes per second the server receives from the client
  uint32_t packetsSec;  // How many packets per second the server receives from the client
  uint32_t connected;
  uint8_t sendCheck[MAX_SENDCHECK+2];
  int32_t todc;
  int8_t patch_folder[PATH_MAX];
  uint32_t patch_steps;
  uint32_t chunk;
  uint8_t IP_Address[16];
  uint32_t connection_index;
} BANANA;

fd_set ReadFDs, WriteFDs, ExceptFDs;

#define MAX_SIMULTANEOUS_CONNECTIONS 6

char dp[TCP_BUFFER_SIZE*4];
int8_t PacketData[TCP_BUFFER_SIZE];

uint8_t patch_packet[TCP_BUFFER_SIZE];
uint32_t patch_size = 0;
patch_data s_data[MAX_PATCHES];
uint32_t serverNumPatches = 0;

void decryptcopy ( void* dest, void* source, uint32_t size );
void encryptcopy ( BANANA* client, void* source, uint32_t size );

CRYPT_SETUP *cipher_ptr;

void display_packet ( uint8_t* buf, int32_t len )
{
  int32_t c, c2, c3, c4;

  c = c2 = c3 = c4 = 0;

  for (c=0;c<len;c++)
  {
    if (c3==16)
    {
      for (;c4<c;c4++)
        if (buf[c4] >= 0x20)
          dp[c2++] = buf[c4];
        else
          dp[c2++] = 0x2E;
      c3 = 0;
      sprintf (&dp[c2++], "\n" );
    }

    if ((c == 0) || !(c % 16))
    {
      sprintf (&dp[c2], "(%04X) ", c);
      c2 += 7;
    }

    sprintf (&dp[c2], "%02X ", buf[c]);
    c2 += 3;
    c3++;
  }

  if ( len % 16 )
  {
    c3 = len;
    while (c3 % 16)
    {
      sprintf (&dp[c2], "   ");
      c2 += 3;
      c3++;
    }
  }

  for (;c4<c;c4++)
    if (buf[c4] >= 0x20)
      dp[c2++] = buf[c4];
    else
      dp[c2++] = 0x2E;

  dp[c2] = 0;
  printf ("%s\n\n", &dp[0]);
}

void convertIPString (char* IPData, uint32_t IPLen, int32_t fromConfig )
{
  uint32_t p,p2,p3;
  char convert_buffer[5];

  p2 = 0;
  p3 = 0;
  for (p=0;p<IPLen;p++)
  {
    if ((IPData[p] > 0x20) && (IPData[p] != 46))
      convert_buffer[p3++] = IPData[p]; else
    {
      convert_buffer[p3] = 0;
      if (IPData[p] == 46) // .
      {

        serverIP[p2] = atoi (&convert_buffer[0]);
        p2++;
        p3 = 0;
        if (p2>3)
        {
          if (fromConfig)
            printf ("tethealla.ini is corrupted. (Failed to read IP information from file!)\n"); else
            printf ("Failed to determine IP address.\n");
          exit (1);
        }
      }
      else
      {
        serverIP[p2] = atoi (&convert_buffer[0]);
        if (p2 != 3)
        {
          if (fromConfig)
            printf ("tethealla.ini is corrupted. (Failed to read IP information from file!)\n"); else
            printf ("Failed to determine IP address.\n");
          exit (1);
        }
        break;
      }
    }
  }
}

int32_t CalculateChecksum(void* data,uint32_t size)
{
    int32_t offset,y,cs = 0xFFFFFFFF;
    for (offset = 0; offset < (long)size; offset++)
    {
        cs ^= *(uint8_t*)((long)data + offset);
        for (y = 0; y < 8; y++)
        {
            if (!(cs & 1)) cs = (cs >> 1) & 0x7FFFFFFF;
            else cs = ((cs >> 1) & 0x7FFFFFFF) ^ 0xEDB88320;
        }
    }
    return (cs ^ 0xFFFFFFFF);
}


void load_config_file()
{
  int32_t config_index = 0;
  char config_data[255];
  uint32_t ch;

  FILE* fp;

  if ( ( fp = fopen ("tethealla.ini", "r" ) ) == NULL )
  {
    printf ("\nThe configuration file tethealla.ini appears to be missing.\n");
    exit (1);
  }
  else
  {
    while (fgets (&config_data[0], 255, fp) != NULL)
    {
      if (config_data[0] != 0x23)
      {
        if ((config_index < 0x04) || (config_index > 0x04))
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
          //memcpy (&mySQL_Host[0], &config_data[0], ch+1);
          break;
        case 0x01:
          // MySQL Username
          //memcpy (&mySQL_Username[0], &config_data[0], ch+1);
          break;
        case 0x02:
          // MySQL Password
          //memcpy (&mySQL_Password[0], &config_data[0], ch+1);
          break;
        case 0x03:
          // MySQL Database
          //memcpy (&mySQL_Database[0], &config_data[0], ch+1);
          break;
        case 0x04:
          // MySQL Port
          //mySQL_Port = atoi (&config_data[0]);
          break;
        case 0x05:
          // Server IP address
          {
            if ((config_data[0] == 0x41) || (config_data[0] == 0x61))
            {
              struct sockaddr_in pn_in;
              struct hostent *pn_host;
              int32_t pn_sockfd, pn_len;
              char pn_buf[512];
              char* pn_ipdata;

              printf ("\n** Determining IP address ... ");

              pn_host = gethostbyname ( "www.pioneer2.net" );
              if (!pn_host) {
                printf ("Could not resolve www.pioneer2.net\n");
                exit (1);
              }

              /* Create a reliable, stream socket using TCP */
              if ((pn_sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
              {
                printf ("Unable to create TCP/IP streaming socket.");
                exit(1);
              }

              /* Construct the server address structure */
              memset(&pn_in, 0, sizeof(pn_in)); /* Zero out structure */
              pn_in.sin_family = AF_INET; /* Internet address family */

              memcpy(&pn_in.sin_addr.s_addr, pn_host->h_addr, 4); /* Web Server IP address */

              pn_in.sin_port = htons(80); /* Web Server port */

              /* Establish the connection to the pioneer2.net Web Server ... */

              if (connect(pn_sockfd, (struct sockaddr *) &pn_in, sizeof(pn_in)) < 0)
              {
                printf ("\nCannot connect to www.pioneer2.net!");
                exit(1);
              }

              /* Process pioneer2.net's response into the serverIP variable. */

              send_to_server ( pn_sockfd, HTTP_REQ );
              pn_len = recv(pn_sockfd, &pn_buf[0], sizeof(pn_buf) - 1, 0);
              close (pn_sockfd);
              pn_buf[pn_len] = 0;
              pn_ipdata = strstr (&pn_buf[0], "/html");
              if (!pn_ipdata)
              {
                printf ("Failed to determine IP address.\n");
              }
              else
                pn_ipdata += 9;

              convertIPString (pn_ipdata, strlen (pn_ipdata), 0 );
            }
            else
            {
              convertIPString (&config_data[0], ch+1, 1);
            }
          }
          break;
        case 0x06:
          // Welcome Message
          break;
        case 0x07:
          // Server Listen Port
          serverPort = atoi (&config_data[0]);
          break;
        case 0x08:
          // Max Client Connections
          serverMaxConnections = atoi (&config_data[0]);
          if ( serverMaxConnections > PATCH_COMPILED_MAX_CONNECTIONS )
          {
             serverMaxConnections = PATCH_COMPILED_MAX_CONNECTIONS;
             printf ("This version of the patch server has not been compiled to handle more than %u patch connections.  Adjusted.\n", PATCH_COMPILED_MAX_CONNECTIONS );
          }
          if ( !serverMaxConnections )
            serverMaxConnections  = PATCH_COMPILED_MAX_CONNECTIONS;
          break;
        case 0x09:
          break;
        case 0x0A:
          // Override IP address (if specified, this IP will be sent out instead of your own to those who connect)
          if ((config_data[0] > 0x30) && (config_data[0] < 0x3A))
          {
            override_on = 1;
            memcpy (&overrideIP[0], &serverIP[0], 4);
            serverIP[0] = 0;
            convertIPString (&config_data[0], ch+1, 1);
          }
          break;
        default:
          break;
        }
        config_index++;
      }
    }
    fclose (fp);
  }

  if (config_index < 0x13)
  {
    printf ("tethealla.ini seems to be corrupted.\n");
    exit (1);
  }

  printf ("  OK!\n");
  printf ("Loading configuration from patch.ini ...");

  // Load patch.ini here
  // Upload throttle

  config_index = 0;

  if ( ( fp = fopen ("patch.ini", "r" ) ) == NULL )
  {
    printf ("\nThe configuration file patch.ini appears to be missing.\n");
    exit (1);
  }
  else
    while (fgets (&config_data[0], 255, fp) != NULL)
    {
      if (config_data[0] != 0x23)
      {
          ch = strlen (&config_data[0]);
          if (config_data[ch-1] == 0x0A)
            config_data[ch--]  = 0x00;
          config_data[ch] = 0;
          if (config_index == 0)
          {
            maxbytes = atoi (&config_data[0]);
            if (maxbytes)
              maxbytes *= 1024;
          }
          config_index++;
      }
    }
  fclose (fp);
}

BANANA * connections[PATCH_COMPILED_MAX_CONNECTIONS];
BANANA * workConnect;

const int8_t serverName[] = { "T\0E\0T\0H\0E\0A\0L\0L\0A\0" };


uint32_t free_connection()
{
  uint32_t fc;
  BANANA* wc;

  for (fc=0;fc<serverMaxConnections;fc++)
  {
    wc = connections[fc];
    if (wc->plySockfd<0)
      return fc;
  }
  return 0xFFFF;
}


void initialize_connection (BANANA* connect)
{
  uint32_t ch, ch2;

  if (connect->plySockfd >= 0)
  {
    ch2 = 0;
    for (ch=0;ch<serverNumConnections;ch++)
    {
      if (serverConnectionList[ch] != connect->connection_index)
        serverConnectionList[ch2++] = serverConnectionList[ch];
    }
    serverNumConnections = ch2;
    close (connect->plySockfd);
  }
  memset (connect, 0, sizeof (BANANA));
  connect->plySockfd = -1;
  connect->lastTick = 0xFFFFFFFF;
  connect->connected = 0xFFFFFFFF;
}


void start_encryption(BANANA* connect)
{
  uint32_t c, c3, c4, connectNum;
  BANANA *workConnect, *c5;

  // Limit the number of connections from an IP address to MAX_SIMULTANEOUS_CONNECTIONS.

  c3 = 0;

  for (c=0;c<serverNumConnections;c++)
  {
    connectNum = serverConnectionList[c];
    workConnect = connections[connectNum];
    //debug ("%s comparing to %s", (char*) &workConnect->IP_Address[0], (char*) &connect->IP_Address[0]);
    if ((!strcmp((char *)workConnect->IP_Address, (char *)connect->IP_Address)) &&
      (workConnect->plySockfd >= 0))
      c3++;
  }

  if (c3 > MAX_SIMULTANEOUS_CONNECTIONS)
  {
    // More than MAX_SIMULTANEOUS_CONNECTIONS connections from a certain IP address...
    // Delete oldest connection to server.
    c4 = 0xFFFFFFFF;
    c5 = NULL;
    for (c=0;c<serverNumConnections;c++)
    {
      connectNum = serverConnectionList[c];
      workConnect = connections[connectNum];
      if ((!strcmp((char *)workConnect->IP_Address, (char *)&connect->IP_Address)) &&
        (workConnect->plySockfd >= 0))
      {
        if (workConnect->connected < c4)
        {
          c4 = workConnect->connected;
          c5 = workConnect;
        }
      }
    }
    if (c5)
    {
      workConnect = c5;
      initialize_connection (workConnect);
    }
  }
  memcpy (&connect->sndbuf[0], &Packet02[0], sizeof (Packet02));
  for (c=0;c<8;c++)
    connect->sndbuf[0x44+c] = (uint8_t) rand() % 255;
  connect->snddata += sizeof (Packet02);

  memcpy (&c, &connect->sndbuf[0x44], 4);
  CRYPT_PC_CreateKeys(&connect->server_cipher,c);
  memcpy (&c, &connect->sndbuf[0x48], 4);
  CRYPT_PC_CreateKeys(&connect->client_cipher,c);
  connect->crypt_on = 1;
  connect->sendCheck[SEND_PACKET_02] = 1;
  connect->connected = (unsigned) servertime;
}

void change_client_folder (unsigned patchNum, BANANA* client);

void Send11 (BANANA* client)
{
  uint32_t ch;

  client->sendCheck[RECEIVE_PACKET_10] = 1;

  for (ch=0;ch<serverNumPatches;ch++)
  {
    if ((client->p_data[ch].file_size != s_data[ch].file_size) ||
      (client->p_data[ch].checksum  != s_data[ch].checksum))
    {
      //debug ("%s mismatch", s_data[ch].file_name);
      client->s_data[client->files_to_send++] = ch;
      client->bytes_to_send += s_data[ch].file_size;
    }
  }

  if (client->files_to_send)
  {
    memset (&client->encryptbuf[0x00], 0, 0x0C);
    memcpy (&client->encryptbuf[0x04], &client->bytes_to_send, 4);
    memcpy (&client->encryptbuf[0x08], &client->files_to_send, 4);
    client->encryptbuf[0x00] = 0x0C;
    client->encryptbuf[0x02] = 0x11;
    cipher_ptr = &client->server_cipher;
    encryptcopy (client, &client->encryptbuf[0x00], 0x0C);
    change_client_folder (client->s_data[0], client);
    client->sending_files = 1; // We're in send mode!
    printf ("(%s) Sending %u files, total bytes: %u\n", client->username, client->files_to_send, client->bytes_to_send);
  }
  else
  {
    workConnect->encryptbuf[0x00] = 0x04;
    workConnect->encryptbuf[0x01] = 0x00;
    workConnect->encryptbuf[0x02] = 0x12;
    workConnect->encryptbuf[0x03] = 0x00;
    cipher_ptr = &workConnect->server_cipher;
    encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
  }
}

void Send0B (BANANA* client)
{
  if (!client->sendCheck[SEND_PACKET_0B])
  {
    client->sendCheck[SEND_PACKET_0B] = 1;
    client->encryptbuf[0x00] = 0x04;
    client->encryptbuf[0x01] = 0x00;
    client->encryptbuf[0x02] = 0x0B;
    client->encryptbuf[0x03] = 0x00;
    cipher_ptr = &client->server_cipher;
    encryptcopy (client, &client->encryptbuf[0x00], 4);
    cipher_ptr = &client->server_cipher;
    encryptcopy (client, &patch_packet[0], patch_size);
  }
}

void Send13 (BANANA* client)
{
  uint16_t Welcome_Size;
  uint8_t port[2];

  Welcome_Size = Welcome_Message_Size + 4;
  memcpy (&client->encryptbuf[0x04], &Welcome_Message[0], Welcome_Message_Size);
  client->encryptbuf[0x02] = 0x13;
  client->encryptbuf[0x03] = 0x00;
  client->encryptbuf[Welcome_Size++] = 0x00;
  client->encryptbuf[Welcome_Size++] = 0x00;
  while (Welcome_Size % 4)
    client->encryptbuf[Welcome_Size++] = 0x00;
  memcpy (&client->encryptbuf[0x00], &Welcome_Size, 2);
  cipher_ptr = &client->server_cipher;
  encryptcopy (client, &client->encryptbuf[0x00], Welcome_Size);
  memset (&client->encryptbuf[0x00], 0, 0x0C);
  client->encryptbuf[0x00] = 0x0C;
  client->encryptbuf[0x02] = 0x14;
  memcpy (&client->encryptbuf[0x04], &serverIP, 4);
  Welcome_Size = serverPort;
  Welcome_Size -= 999;
  memcpy (&port, &Welcome_Size, 2);
  client->encryptbuf[0x08] = port[1];
  client->encryptbuf[0x09] = port[0];
  cipher_ptr = &client->server_cipher;
  encryptcopy (client, &client->encryptbuf[0x00], 0x0C);
}

void DataProcessPacket (BANANA* client)
{
  uint32_t patch_index;

  switch (client->decryptbuf[0x02])
  {
  case 0x02:
    // Acknowledging welcome packet
    client->encryptbuf[0x00] = 0x04;
    client->encryptbuf[0x01] = 0x00;
    client->encryptbuf[0x02] = 0x04;
    client->encryptbuf[0x03] = 0x00;
    cipher_ptr = &client->server_cipher;
    encryptcopy (client, &client->encryptbuf[0x00], 4);
    break;
  case 0x04:
    // Client sending user name to begin downloading patch data
    memcpy (&client->username[0], &client->decryptbuf[0x10], 16);
    Send0B (client); // Data time...
    break;
  case 0x0F:
    // Client sending status of current patch file
    memcpy (&patch_index, &client->decryptbuf[0x04], 4);
    if (patch_index < MAX_PATCHES)
    {
      memcpy (&client->p_data[patch_index].checksum,  &client->decryptbuf[0x08], 4);
      memcpy (&client->p_data[patch_index].file_size, &client->decryptbuf[0x0C], 4);
    }
    break;
  case 0x10:
    // Client done sending all patch file status
    if (!client->sendCheck[RECEIVE_PACKET_10])
      Send11 (client);
    break;
  }
}

void PatchProcessPacket (BANANA* client)
{
  switch (client->decryptbuf[0x02])
  {
  case 0x02:
    // Acknowledging welcome packet
    client->encryptbuf[0x00] = 0x04;
    client->encryptbuf[0x01] = 0x00;
    client->encryptbuf[0x02] = 0x04;
    client->encryptbuf[0x03] = 0x00;
    cipher_ptr = &client->server_cipher;
    encryptcopy (client, &client->encryptbuf[0x00], 4);
    break;
  case 0x04:
    // Client sending user name to begin downloading patch data
    memcpy (&client->username[0], &client->decryptbuf[0x10], 16);
    Send13 (client); // Welcome packet
    break;
  default:
    break;
  }
}

char patch_folder[PATH_MAX] = {0};
uint32_t patch_steps = 0;
int32_t now_folder = -1;

void scanpatches(char *path, bool recursive);
int32_t fixpath(char *inpath, char *outpath);

void change_client_folder (unsigned patchNum, BANANA* client)
{
  uint32_t ch, ch2, ch3;

  if (strcmp((char *)&client->patch_folder[0], (char *)s_data[patchNum].folder) != 0)
  {
    // Client not in the right folder...

    while (client->patch_steps)
    {
      client->encryptbuf[0x00] = 0x04;
      client->encryptbuf[0x01] = 0x00;
      client->encryptbuf[0x02] = 0x0A;
      client->encryptbuf[0x03] = 0x00;
      cipher_ptr = &client->server_cipher;
      encryptcopy (client, &client->encryptbuf[0x00], 4);
      client->patch_steps--;
    }

    if (s_data[patchNum].patch_folders[0] != 0x2E)
    {
      ch = 0;
      while (ch<s_data[patchNum].patch_folders_size)
      {
        memset (&client->encryptbuf[0x00], 0, 0x44);
        client->encryptbuf[0x00] = 0x44;
        client->encryptbuf[0x02] = 0x09;
        ch3 = 0;
        for (ch2=ch;ch2<s_data[patchNum].patch_folders_size;ch2++)
        {
          if (s_data[patchNum].patch_folders[ch2] == 0x00)
            break;
          ch3++;
        }
        strcat ((char *)&client->encryptbuf[0x04], (char *)&s_data[patchNum].patch_folders[ch]);
        ch += (ch3 + 1);
        cipher_ptr = &client->server_cipher;
        encryptcopy (client, &client->encryptbuf[0x00], 0x44);
      }
    }
    memcpy (&client->patch_folder[0], &s_data[patchNum].folder, PATH_MAX);
    client->patch_steps = s_data[patchNum].patch_steps;
  }
  // Now let's send the information about the file coming in...
  memset (&client->encryptbuf[0x00], 0, 0x3C);
  client->encryptbuf[0x00] = 0x3C;
  client->encryptbuf[0x02] = 0x06;
  memcpy (&client->encryptbuf[0x08], &s_data[patchNum].file_size, 4);
  strcat ((char *)&client->encryptbuf[0x0C], (char *)s_data[patchNum].file_name);
  cipher_ptr = &client->server_cipher;
  encryptcopy (client, &client->encryptbuf[0x00], 0x3C);
}

void change_patch_folder (unsigned patchNum)
{
  uint32_t ch, ch2, ch3;

  if (strcmp(patch_folder, (char *)s_data[patchNum].folder) != 0)
  {
    // Not in the right folder...
    while (patch_steps)
    {
      patch_packet[patch_size++] = 0x04;
      patch_packet[patch_size++] = 0x00;
      patch_packet[patch_size++] = 0x0A;
      patch_packet[patch_size++] = 0x00;
      patch_steps--;
    }

    if (s_data[patchNum].patch_folders[0] != 0x2E)
    {
      ch = 0;
      while (ch<s_data[patchNum].patch_folders_size)
      {
        memset (&patch_packet[patch_size], 0, 0x44);
        patch_packet[patch_size+0x00] = 0x44;
        patch_packet[patch_size+0x02] = 0x09;
        ch3 = 0;
        for (ch2=ch;ch2<s_data[patchNum].patch_folders_size;ch2++)
        {
          if (s_data[patchNum].patch_folders[ch2] == 0x00)
            break;
          ch3++;
        }
        strcat ((char *)&patch_packet[patch_size+0x04], (char *)&s_data[patchNum].patch_folders[ch]);
        ch += (ch3 + 1);
        patch_size += 0x44;
      }
    }
    memcpy (&patch_folder[0], &s_data[patchNum].folder, PATH_MAX);
    patch_steps = s_data[patchNum].patch_steps;
  }
}

void scanpatches(char *_path, bool recursive) {
  DIR *dir;
  struct dirent *entry;
  char tmppath[PATH_MAX] = {0};
  FILE *pf;
  uint64_t f_size;
  uint32_t f_checksum;
  uint8_t *pd;
  uint32_t ch, ch2, ch3;

  if(!(dir = opendir(_path))) return;

  now_folder++;

  while((entry = readdir(dir)) != NULL) {
    if(entry->d_type == DT_DIR) {
      fixpath(_path, tmppath);
      strcat(tmppath, entry->d_name);
      fixpath(tmppath, tmppath);

      if(recursive) {
        char path[1024];
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        snprintf(path, sizeof(path), "%s/%s", _path, entry->d_name);
        scanpatches(path, true);
      }
    } else {
        fixpath(_path, tmppath);
        s_data[serverNumPatches].full_file_name[0] = 0;

        snprintf(
            (char *)s_data[serverNumPatches].full_file_name,
            sizeof(s_data[serverNumPatches].full_file_name),
            "%s/%s", _path, entry->d_name);

        pf = fopen ((char *)s_data[serverNumPatches].full_file_name, "rb");
        fseek(pf, 0L, SEEK_END);
        f_size = ftell(pf);
        rewind(pf);

        pd = malloc (f_size);
        if(fread ( pd, 1, f_size, pf ) != f_size)
        {
          printf("Failed to read file...\n");
          exit(0);
        }
        fclose ( pf );

        f_checksum = CalculateChecksum ( pd, f_size );
        free ( pd );
        printf ("%s  Bytes: %lu  Checksum: %08x\n",s_data[serverNumPatches].full_file_name , f_size, f_checksum );
        s_data[serverNumPatches].file_size  = f_size;
        s_data[serverNumPatches].checksum = f_checksum;
        strcpy((char *)s_data[serverNumPatches].file_name, (char *)entry->d_name);
        snprintf(
            (char *)s_data[serverNumPatches].folder,
            sizeof(s_data[serverNumPatches].folder),
            "%s/", _path);

        ch2 = 0;
        ch3 = 0;
        if (now_folder)
        {
          for (ch=0;ch<strlen(&tmppath[0]);ch++)
          {
            if (tmppath[ch] != 0x2F)
              s_data[serverNumPatches].patch_folders[ch2++] = tmppath[ch];
            else
            {
              s_data[serverNumPatches].patch_folders[ch2++] = 0;
              strlwr ((char *)&s_data[serverNumPatches].patch_folders[ch3]);
              if (strcmp((char *)&s_data[serverNumPatches].patch_folders[ch3],"patches") == 0)
              {
                ch2 = ch3;
                s_data[serverNumPatches].patch_folders[ch2] = 0;
              }
              else
                ch3 = ch2;
            }
          }
          s_data[serverNumPatches].patch_folders_size = ch2;
        }
        else
        {
          s_data[serverNumPatches].patch_folders[0] = 0x2E;
          s_data[serverNumPatches].patch_folders[1] = 0;
          s_data[serverNumPatches].patch_folders_size = 1;
        }

        s_data[serverNumPatches++].patch_steps = now_folder;
        change_patch_folder (serverNumPatches - 1);
        ch = serverNumPatches - 1;
        memset (&patch_packet[patch_size], 0, 0x28);
        memcpy (&patch_packet[patch_size+4], &ch, 4);
        strcat ((char *)&patch_packet[patch_size+8], (char *)entry->d_name);
        patch_packet[patch_size]   = 0x28;
        patch_packet[patch_size+2] = 0x0C;
        patch_size += 0x28;
      }
  }

  now_folder--;
}

int32_t fixpath(char *inpath, char *outpath)
{
  int32_t   n=0;

  strcpy(outpath,inpath);

  while(inpath[n]) n++;

  if(inpath[n-1] != '/')
  {
    strcat(outpath,"/");
    return 1;
  }

  return 0;
}


/********************************************************
**
**    main  :-
**
********************************************************/

int32_t main( int32_t argc, char * argv[] )
{
  uint32_t ch,ch2;
  struct in_addr patch_in;
  struct in_addr data_in;
  struct sockaddr_in listen_in;
  uint32_t listen_length;
  int32_t patch_sockfd = -1, data_sockfd;
  int32_t pkt_len, pkt_c, bytes_sent;
  uint16_t this_packet;
  uint16_t *w;
  uint16_t *w2;
  uint32_t num_sends = 0;
  patch_data *pd;

  FILE* fp;
  //int wserror;
  uint8_t tmprcv[TCP_BUFFER_SIZE];
  uint32_t connectNum;
  uint32_t to_send, checksum;
  int32_t data_send, data_remaining;

  dp[0] = 0;

  strcat (&dp[0], "Tethealla Patch Server version ");
  strcat (&dp[0], SERVER_VERSION );
  strcat (&dp[0], " coded by Sodaboy");

  printf ("\nTethealla Patch Server version %s  Copyright (C) 2008  Terry Chatman Jr.\n", SERVER_VERSION);
  printf ("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
  printf ("This program comes with ABSOLUTELY NO WARRANTY; for details\n");
  printf ("see section 15 in gpl-3.0.txt\n");
    printf ("This is free software, and you are welcome to redistribute it\n");
    printf ("under certain conditions; see gpl-3.0.txt for details.\n");

  for (ch=0;ch<5;ch++)
  {
    printf (".");
  }
  printf ("\n\n");

  data_remaining = 0;

  srand ( (unsigned) time(NULL) );

  printf ("Loading configuration from tethealla.ini ...");
  load_config_file();
  if (maxbytes)
    data_remaining = maxbytes;
  printf ("  OK!\n");
  printf ("\nPatch server parameters\n");
  printf ("///////////////////////\n");
  if (override_on)
    printf ("NOTE: IP override feature is turned on.\nThe server will bind to %u.%u.%u.%u but will send out the IP listed below.\n", overrideIP[0], overrideIP[1], overrideIP[2], overrideIP[3] );
  printf ("IP: %u.%u.%u.%u\n", serverIP[0], serverIP[1], serverIP[2], serverIP[3] );
  printf ("Patch Port: %u\n", serverPort - 1000 );
  printf ("Data Port: %u\n", serverPort - 999 );
  printf ("Maximum Connections: %u\n", serverMaxConnections );
  printf ("Upload speed: ");
  if (maxbytes)
    printf ("%lu KB/s\n", maxbytes / 1024L);
  else
    printf ("Max\n");
  printf ("Allocating %lu bytes of memory for connections...", sizeof (BANANA) * serverMaxConnections );
  for (ch=0;ch<serverMaxConnections;ch++)
  {
    connections[ch] = malloc ( sizeof (BANANA) );
    if ( !connections[ch] )
    {
      printf ("Out of memory!\n");
      exit (1);
    }
    initialize_connection (connections[ch]);
  }
  printf (" OK!\n\n");

  printf ("Preparing patch data...\n");
  printf ("Reading from folder \"patches\"...\n");

  memset (&patch_packet[patch_size], 0, 0x44);
  patch_packet[patch_size+0x00] = 0x44;
  patch_packet[patch_size+0x02] = 0x09;
  patch_packet[patch_size+0x04] = 0x2E;
  patch_size += 0x44;
  scanpatches ("patches",1);
  patch_packet[patch_size++] = 0x04;
  patch_packet[patch_size++] = 0x00;
  patch_packet[patch_size++] = 0x0A;
  patch_packet[patch_size++] = 0x00;
  patch_packet[patch_size++] = 0x04;
  patch_packet[patch_size++] = 0x00;
  patch_packet[patch_size++] = 0x0D;
  patch_packet[patch_size++] = 0x00;
  printf ("\nDone!\n\n");

  if (!serverNumPatches)
  {
    printf ("There are no patches to send.\nYou need at least one patch file to send or check.\n");
    exit (1);
  }

  printf ("Loading welcome.txt ...");
  fp = fopen ("welcome.txt","rb");
  if (!fp)
  {
    printf ("\nwelcome.txt seems to be missing.\nPlease be sure it's in the same folder as patch_server.exe\n");
    exit (1);
  }
  fseek ( fp, 0, SEEK_END );
  ch = ftell ( fp );
  fseek ( fp, 0, SEEK_SET );
  if ( ch > 4096 )
     ch = 4096;
  if(!fread (&PacketData[0], 1, ch, fp ))
  {
    printf("Failed to read packet data...\n");
    exit(0);
  }
  fclose ( fp );

  w  = (uint16_t*) &PacketData[0];
  w2 = (uint16_t*) &Welcome_Message[0];
  Welcome_Message_Size = 0;
  for ( ch2 = 0; ch2 < ch; ch2 += 2 )
  {
    if (*w == 0x0024)
      *w =  0x0009; // Change $ to 0x09
    if (*w != 0x000D)
    {
      *(w2++) = *w;
      Welcome_Message_Size += 2;
    }
    w++;
  }

  *w2 = 0x0000;

  printf ("  (%u bytes) OK!\n\n", Welcome_Message_Size);

  /* Open the PSO BB Patch Server Port... */

  printf ("Opening server patch port %u for connections.\n", serverPort - 1000);

#ifdef USEADDR_ANY
  patch_in.s_addr = INADDR_ANY;
#else
  if (override_on)
    memcpy (&patch_in.s_addr, &overrideIP[0], 4 );
  else
    memcpy (&patch_in.s_addr, &serverIP[0], 4 );
#endif

  patch_sockfd = tcp_sock_open( patch_in, serverPort - 1000 );

  tcp_listen (patch_sockfd);

#ifdef USEADDR_ANY
  data_in.s_addr = INADDR_ANY;
#else
  if (override_on)
    memcpy (&data_in.s_addr, &overrideIP[0], 4 );
  else
    memcpy (&data_in.s_addr, &serverIP[0], 4 );
#endif

  printf ("Opening server data port %u for connections.\n", serverPort - 999);

  data_sockfd = tcp_sock_open( data_in, serverPort - 999 );

  tcp_listen (data_sockfd);

  if ((patch_sockfd<0) || (data_sockfd<0))
  {
    printf ("Failed to open port for connections.\n");
    exit (1);
  }

  printf ("\nListening...\n");

  for (;;)
  {
    int32_t nfds = 0;

    /* Ping pong?! */

    servertime = time(NULL);

    if ((maxbytes) && (sendtime != (unsigned) servertime))
    {
      sendtime  = (unsigned) servertime;
      data_remaining = maxbytes;
    }

    /* Clear socket activity flags. */

    FD_ZERO (&ReadFDs);
    FD_ZERO (&WriteFDs);
    FD_ZERO (&ExceptFDs);

    num_sends = 0;

    for (ch=0;ch<serverNumConnections;ch++)
    {
      connectNum = serverConnectionList[ch];
      workConnect = connections[connectNum];

      if (workConnect->plySockfd >= 0)
      {
        if (workConnect->packetdata)
        {
          memcpy (&this_packet, &workConnect->packet[workConnect->packetread], 2);
          memcpy (&workConnect->decryptbuf[0], &workConnect->packet[workConnect->packetread], this_packet);

          //debug ("Received from client:%u", this_packet);
          //display_packet (&workConnect->decryptbuf[0], this_packet);

          if (workConnect->patch)
            DataProcessPacket (workConnect);
          else
            PatchProcessPacket (workConnect);

          workConnect->packetread += this_packet;
          if (workConnect->packetread == workConnect->packetdata)
            workConnect->packetread = workConnect->packetdata = 0;
        }

        if (workConnect->lastTick != (unsigned) servertime)
        {
          if (workConnect->lastTick > (unsigned) servertime)
            ch2 = 1;
          else
            ch2 = 1 + ((unsigned) servertime - workConnect->lastTick);
          workConnect->lastTick = (unsigned) servertime;
          workConnect->packetsSec /= ch2;
          workConnect->toBytesSec /= ch2;
          workConnect->fromBytesSec /= ch2;
        }

        FD_SET (workConnect->plySockfd, &ReadFDs);
        nfds = max (nfds, workConnect->plySockfd);
        FD_SET (workConnect->plySockfd, &ExceptFDs);
        nfds = max (nfds, workConnect->plySockfd);

        if ((!maxbytes) || (data_remaining))
        {
          if (workConnect->snddata - workConnect->sndwritten)
          {
            FD_SET (workConnect->plySockfd, &WriteFDs);
            nfds = max (nfds, workConnect->plySockfd);
          }
          else
          {
            // Send remaining patch data here...
            // if sending_files and stuff left to go
            if (workConnect->sending_files)
            {
              num_sends++;
              pd = &s_data[workConnect->s_data[workConnect->current_file]];
              fp = fopen ((char *)pd->full_file_name, "rb");
              fseek (fp, workConnect->cfile_index, SEEK_SET);
              to_send = pd->file_size - workConnect->cfile_index;
              if (to_send > 24576)
                to_send = 24576;
              if (!fread (&PacketData[0x10], 1, to_send, fp))
              {
                printf("Failed to read packet data...\n");
                exit(0);
              }
              fclose (fp);
              workConnect->cfile_index += to_send;
              checksum = CalculateChecksum ( &PacketData[0x10], to_send);
              memset (&PacketData[0x00], 0, 0x10);
              PacketData[0x02] = 0x07;
              memcpy (&PacketData[0x04], &workConnect->chunk, 4);
              memcpy (&PacketData[0x08], &checksum, 4);
              memcpy (&PacketData[0x0C], &to_send,  4);
              to_send += 0x10;
              while (to_send % 4)
                PacketData[to_send++] = 0x00;
              memcpy (&PacketData[0x00], &to_send, 2);
              cipher_ptr = &workConnect->server_cipher;
              encryptcopy (workConnect, &PacketData[0x00], to_send);
              workConnect->chunk++;
              if (workConnect->cfile_index == pd->file_size)
              {
                // File's done...
                memset (&workConnect->encryptbuf[0x00], 0, 8);
                workConnect->encryptbuf[0x00] = 0x08;
                workConnect->encryptbuf[0x02] = 0x08;
                cipher_ptr = &workConnect->server_cipher;
                encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 8);
                workConnect->chunk = 0;
                workConnect->cfile_index = 0;
                // Are we completely done?
                workConnect->current_file++;
                if (workConnect->current_file == workConnect->files_to_send)
                {
                  // Hell yeah we are!
                  while (workConnect->patch_steps)
                  {
                    workConnect->encryptbuf[0x00] = 0x04;
                    workConnect->encryptbuf[0x01] = 0x00;
                    workConnect->encryptbuf[0x02] = 0x0A;
                    workConnect->encryptbuf[0x03] = 0x00;
                    cipher_ptr = &workConnect->server_cipher;
                    encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
                    workConnect->patch_steps--;
                  }
                  workConnect->sending_files = 0;
                  workConnect->encryptbuf[0x00] = 0x04;
                  workConnect->encryptbuf[0x01] = 0x00;
                  workConnect->encryptbuf[0x02] = 0x0A;
                  workConnect->encryptbuf[0x03] = 0x00;
                  cipher_ptr = &workConnect->server_cipher;
                  encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
                  workConnect->encryptbuf[0x00] = 0x04;
                  workConnect->encryptbuf[0x01] = 0x00;
                  workConnect->encryptbuf[0x02] = 0x12;
                  workConnect->encryptbuf[0x03] = 0x00;
                  cipher_ptr = &workConnect->server_cipher;
                  encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
                }
                else
                  change_client_folder (workConnect->s_data[workConnect->current_file], workConnect);
              }
            }
          }
        }
      }
    }

    FD_SET (patch_sockfd, &ReadFDs);
    nfds = max (nfds, patch_sockfd);
    FD_SET (data_sockfd, &ReadFDs);
    nfds = max (nfds, data_sockfd);

    /* Check sockets for activity. */

    struct timeval select_timeout = {
      0,
      5000
    };

    if ( select ( nfds + 1, &ReadFDs, &WriteFDs, &ExceptFDs, &select_timeout ) > 0 )
    {
      if (FD_ISSET (patch_sockfd, &ReadFDs))
      {
        // Someone's attempting to connect to the patch server.
        ch = free_connection();
        if (ch != 0xFFFF)
        {
          listen_length = sizeof (listen_in);
          workConnect = connections[ch];
          if ( ( workConnect->plySockfd = tcp_accept ( patch_sockfd, (struct sockaddr*) &listen_in, &listen_length ) ) >= 0 )
          {
            workConnect->connection_index = ch;
            serverConnectionList[serverNumConnections++] = ch;
            memcpy ( &workConnect->IP_Address[0], inet_ntoa (listen_in.sin_addr), 16 );
            printf ("Accepted PATCH connection from %s:%u\n", workConnect->IP_Address, listen_in.sin_port );
            workConnect->patch = 0;
            start_encryption (workConnect);
          }
        }
      }


      if (FD_ISSET (data_sockfd, &ReadFDs))
      {
        // Someone's attempting to connect to the patch server.
        ch = free_connection();
        if (ch != 0xFFFF)
        {
          listen_length = sizeof (listen_in);
          workConnect = connections[ch];
          if ( ( workConnect->plySockfd = tcp_accept ( data_sockfd, (struct sockaddr*) &listen_in, &listen_length ) ) >= 0 )
          {
            workConnect->connection_index = ch;
            serverConnectionList[serverNumConnections++] = ch;
            memcpy ( &workConnect->IP_Address[0], inet_ntoa (listen_in.sin_addr), 16 );
            printf ("Accepted DATA connection from %s:%u\n", workConnect->IP_Address, listen_in.sin_port );
            workConnect->patch = 1;
            start_encryption (workConnect);
          }
        }
      }


      // Process client connections

      for (ch=0;ch<serverNumConnections;ch++)
      {
        connectNum = serverConnectionList[ch];
        workConnect = connections[connectNum];

        if (workConnect->plySockfd >= 0)
        {
          if (FD_ISSET(workConnect->plySockfd, &ExceptFDs)) // Exception?
            initialize_connection (workConnect);

          if (FD_ISSET(workConnect->plySockfd, &ReadFDs))
          {
            // Read shit.
            if ( ( pkt_len = recv (workConnect->plySockfd, &tmprcv[0], TCP_BUFFER_SIZE - 1, 0) ) <= 0 )
            {
              /*
              wserror = WSAGetLastError();
              printf ("Could not read data from client...\n");
              printf ("Socket Error %u.\n", wserror );
              */
              initialize_connection (workConnect);
            }
            else
            {
              workConnect->fromBytesSec += (unsigned) pkt_len;
              // Work with it.
              for (pkt_c=0;pkt_c<pkt_len;pkt_c++)
              {
                workConnect->rcvbuf[workConnect->rcvread++] = tmprcv[pkt_c];

                if (workConnect->rcvread == 4)
                {
                  /* Decrypt the packet header after receiving 8 bytes. */

                  cipher_ptr = &workConnect->client_cipher;

                  decryptcopy ( &workConnect->peekbuf[0], &workConnect->rcvbuf[0], 4 );

                  /* Make sure we're expecting a multiple of 8 bytes. */

                  memcpy ( &workConnect->expect, &workConnect->peekbuf[0], 2 );

                  if ( workConnect->expect % 4 )
                    workConnect->expect += ( 4 - ( workConnect->expect % 4 ) );

                  if ( workConnect->expect > TCP_BUFFER_SIZE )
                  {
                    initialize_connection ( workConnect );
                    break;
                  }
                }

                if ( ( workConnect->rcvread == workConnect->expect ) && ( workConnect->expect != 0 ) )
                {
                  if ( workConnect->packetdata + workConnect->expect > TCP_BUFFER_SIZE )
                  {
                    initialize_connection ( workConnect );
                    break;
                  }
                  else
                  {
                    /* Decrypt the rest of the data if needed. */

                    cipher_ptr = &workConnect->client_cipher;

                    memcpy ( &workConnect->packet[workConnect->packetdata], &workConnect->peekbuf[0], 4 );

                    if ( workConnect->rcvread > 4 )
                      decryptcopy ( &workConnect->packet[workConnect->packetdata + 4], &workConnect->rcvbuf[4], workConnect->expect - 4 );

                    memcpy ( &this_packet, &workConnect->peekbuf[0], 2 );
                    workConnect->packetdata += this_packet;

                    workConnect->packetsSec ++;

                    workConnect->rcvread = 0;
                  }
                }
              }
            }
          }

          if (FD_ISSET(workConnect->plySockfd, &WriteFDs))
          {
            // Write shit

            data_send = workConnect->snddata - workConnect->sndwritten;

            if ((maxbytes) && (workConnect->sending_files)) // We throttling?
            {
              if ( num_sends )
                data_send /= num_sends;

              if ( data_send > data_remaining )
                 data_send = data_remaining;

              if ( data_send )
                data_remaining -= data_send;
            }

            if ( data_send )
            {
              bytes_sent = send (workConnect->plySockfd, &workConnect->sndbuf[workConnect->sndwritten],
                data_send, 0);
              if (bytes_sent == SOCKET_ERROR)
              {
                /*
                wserror = WSAGetLastError();
                printf ("Could not send data to client...\n");
                printf ("Socket Error %u.\n", wserror );
                */
                initialize_connection (workConnect);
              }
              else
              {
                workConnect->sndwritten += bytes_sent;
                workConnect->toBytesSec += (unsigned) bytes_sent;
              }

              if (workConnect->sndwritten == workConnect->snddata)
                workConnect->sndwritten = workConnect->snddata = 0;

            }
          }

          if (workConnect->todc)
            initialize_connection (workConnect);
        }
      }
    }
  }
  return 0;
}


void send_to_server(int sock, char* packet)
{
 int32_t pktlen;

 pktlen = strlen (packet);

  if (send(sock, packet, pktlen, 0) != pktlen)
  {
    printf ("send_to_server(): failure");
    exit(1);
  }

}

int32_t receive_from_server(int sock, char* packet)
{
 int32_t pktlen;

  if ((pktlen = recv(sock, packet, TCP_BUFFER_SIZE - 1, 0)) <= 0)
  {
    printf ("receive_from_server(): failure");
    exit(1);
  }
  packet[pktlen] = 0;
  return pktlen;
}

void tcp_listen (int sockfd)
{
  if (listen(sockfd, 10) < 0)
  {
    debug_perror ("Could not listen for connection");
    exit(1);
  }
}

int32_t tcp_accept (int sockfd, struct sockaddr *client_addr, uint32_t *addr_len )
{
  int32_t fd;

  if ((fd = accept (sockfd, client_addr, addr_len)) < 0)
    debug_perror ("Could not accept connection");

  return (fd);
}

int32_t tcp_sock_connect(char* dest_addr, int32_t port)
{
  int32_t fd;
  struct sockaddr_in sa;

  /* Clear it out */
  memset((void *)&sa, 0, sizeof(sa));

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  /* Error */
  if( fd < 0 )
    debug_perror("Could not create socket");
  else
  {

    memset (&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr (dest_addr);
    sa.sin_port = htons((uint16_t) port);

    if (connect(fd, (struct sockaddr*) &sa, sizeof(sa)) < 0)
      debug_perror("Could not make TCP connection");
    else
      debug ("tcp_sock_connect %s:%u", inet_ntoa (sa.sin_addr), sa.sin_port );
  }
  return(fd);
}

/*****************************************************************************/
int32_t tcp_sock_open(struct in_addr ip, int32_t port)
{
  int32_t fd, turn_on_option_flag = 1;

  struct sockaddr_in sa;

  /* Clear it out */
  memset((void *)&sa, 0, sizeof(sa));

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  /* Error */
  if( fd < 0 ){
    debug_perror("Could not create socket");
    exit(1);
  }

  sa.sin_family = AF_INET;
  memcpy((void *)&sa.sin_addr, (void *)&ip, sizeof(struct in_addr));
  sa.sin_port = htons((uint16_t) port);

  /* Reuse port (ICS?) */

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &turn_on_option_flag, sizeof(turn_on_option_flag));

  /* bind() the socket to the interface */
  if (bind(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0){
    debug_perror("Could not bind to port");
    exit(1);
  }

  return(fd);
}

/*****************************************************************************
* same as debug_perror but writes to debug output.
*
*****************************************************************************/
void debug_perror( char * msg ) {
  debug( "%s : %s\n" , msg , strerror(errno) );
}
/*****************************************************************************/
void debug(char *fmt, ...)
{
#define MAX_MESG_LEN 1024

  va_list args;
  char text[ MAX_MESG_LEN ];

  va_start (args, fmt);
  strcpy (text + vsprintf( text,fmt,args), "\r\n");
  va_end (args);

  fprintf( stderr, "%s", text);
}


void CRYPT_PC_MixKeys(CRYPT_SETUP* pc)
{
    uint32_t esi,edi,eax,ebp,edx;
    edi = 1;
    edx = 0x18;
    eax = edi;
    while (edx > 0)
    {
        esi = pc->keys[eax + 0x1F];
        ebp = pc->keys[eax];
        ebp = ebp - esi;
        pc->keys[eax] = ebp;
        eax++;
        edx--;
    }
    edi = 0x19;
    edx = 0x1F;
    eax = edi;
    while (edx > 0)
    {
        esi = pc->keys[eax - 0x18];
        ebp = pc->keys[eax];
        ebp = ebp - esi;
        pc->keys[eax] = ebp;
        eax++;
        edx--;
    }
}

void CRYPT_PC_CreateKeys(CRYPT_SETUP* pc,uint32_t val)
{
    uint32_t esi,ebx,edi,eax,edx,var1;
    esi = 1;
    ebx = val;
    edi = 0x15;
    pc->keys[56] = ebx;
    pc->keys[55] = ebx;
    while (edi <= 0x46E)
    {
        eax = edi;
        var1 = eax / 55;
        edx = eax - (var1 * 55);
        ebx = ebx - esi;
        edi = edi + 0x15;
        pc->keys[edx] = esi;
        esi = ebx;
        ebx = pc->keys[edx];
    }
    CRYPT_PC_MixKeys(pc);
    CRYPT_PC_MixKeys(pc);
    CRYPT_PC_MixKeys(pc);
    CRYPT_PC_MixKeys(pc);
    pc->pc_posn = 56;
}

uint32_t CRYPT_PC_GetNextKey(CRYPT_SETUP* pc)
{
    uint32_t re;
    if (pc->pc_posn == 56)
    {
        CRYPT_PC_MixKeys(pc);
        pc->pc_posn = 1;
    }
    re = pc->keys[pc->pc_posn];
    pc->pc_posn++;
    return re;
}

void CRYPT_PC_CryptData(CRYPT_SETUP* pc,void* data,uint32_t size)
{
    uint32_t x;
    for (x = 0; x < size; x += 4) *(uint32_t*)((intptr_t)data + x) ^= CRYPT_PC_GetNextKey(pc);
}

void decryptcopy ( void* dest, void* source, uint32_t size )
{
  CRYPT_PC_CryptData(cipher_ptr,source,size);
  memcpy (dest,source,size);
}

void encryptcopy ( BANANA* client, void* source, uint32_t size )
{
  uint8_t* dest;

  if (TCP_BUFFER_SIZE - client->snddata < ( (int) size + 7 ) )
    client->todc = 1;
  else
  {
    dest = &client->sndbuf[client->snddata];
    memcpy (dest,source,size);
    while (size % 4)
      dest[size++] = 0x00;
    client->snddata += (int) size;

    CRYPT_PC_CryptData(cipher_ptr,dest,size);
  }
}
