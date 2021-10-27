#define NO_ALIGN __attribute__ ((packed))

typedef struct st_ptdata
{
  uint8_t weapon_ratio[12]; // high = 0x0D
  int8_t weapon_minrank[12];
  uint8_t weapon_reserved[12]; // ??
  uint8_t power_pattern[9][4];
  uint16_t percent_pattern[23][6];
  uint8_t area_pattern[30];
  uint8_t percent_attachment[6][10];
  uint8_t element_ranking[10];
  uint8_t element_probability[10];
  uint8_t armor_ranking[5];
  uint8_t slot_ranking[5];
  uint8_t unit_level[10];
  uint16_t tool_frequency[28][10];
  uint8_t tech_frequency[19][10];
  int8_t tech_levels[19][20];
  uint8_t enemy_dar[100];
  uint16_t enemy_meseta[100][2];
  int8_t enemy_drop[100];
  uint16_t box_meseta[10][2];
  uint8_t reserved[0x1000-0x8C8];
} NO_ALIGN PTDATA;

/* Ban Structure */

typedef struct st_bandata
{
  uint32_t guildcard;
  uint32_t type; // 1 = account, 2 = ipaddr, 3 = hwinfo
  uint32_t ipaddr;
  int64_t hwinfo;
} BANDATA;


/* Saved Lobby Structure */

typedef struct st_saveLobby {
  uint32_t guildcard;
  uint16_t lobby;
} saveLobby;


/* Weapon pmt structure */

typedef struct st_weappmt
{
  // Starts @ 0x4348
  uint32_t index;
  int16_t model;
  int16_t skin;
  int16_t unknown1;
  int16_t unknown2;
  uint16_t equippable;
  int16_t atpmin;
  int16_t atpmax;
  int16_t atpreq;
  int16_t mstreq;
  int16_t atareq;
  int16_t mstadd;
  uint8_t grind;
  uint8_t photon_color;
  uint8_t special_type;
  uint8_t ataadd;
  uint8_t unknown4[14];
} NO_ALIGN weappmt;


/* Armor pmt structure */

typedef struct st_armorpmt
{
  // Starts @ 0x40 with barriers (Barrier and armor share the same structure...)
  // Armors start @ 0x14f0
  uint32_t index;
  int16_t model;
  int16_t skin;
  int16_t u1;
  int16_t u2;
  int16_t dfp;
  int16_t evp;
  int16_t u3;
  uint16_t equippable;
  uint8_t level;
  uint8_t efr;
  uint8_t eth;
  uint8_t eic;
  uint8_t edk;
  uint8_t elt;
  uint8_t dfp_var;
  uint8_t evp_var;
  int16_t u4;
  int16_t u5;
} NO_ALIGN armorpmt;


/* Battle parameter structure */

typedef struct st_battleparam {
  uint16_t ATP;
  uint16_t MST;
  uint16_t EVP;
  uint16_t HP;
  uint16_t DFP;
  uint16_t ATA;
  uint16_t LCK;
  uint16_t ESP;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
  uint32_t XP;
  uint32_t reserved4;
} NO_ALIGN BATTLEPARAM;


/* Character Data Structure */

typedef struct st_playerLevel {
  uint8_t ATP;
  uint8_t MST;
  uint8_t EVP;
  uint8_t HP;
  uint8_t DFP;
  uint8_t ATA;
  uint8_t LCK;
  uint8_t TP;
  uint32_t XP;
} NO_ALIGN playerLevel;


/* Mag Structure */

typedef struct st_mag
{
  uint8_t two; // "02" =P
  uint8_t mtype;
  uint8_t level;
  uint8_t blasts;
  int16_t defense;
  int16_t power;
  int16_t dex;
  int16_t mind;
  uint32_t itemid;
  int8_t synchro;
  uint8_t IQ;
  uint8_t PBflags;
  uint8_t color;
} NO_ALIGN MAG;


/* Item Structure (Without Flags) */

typedef struct st_item {
  uint8_t data[12]; // the standard $setitem1 - $setitem3 fare
  uint32_t itemid; // player item id
  uint8_t data2[4]; // $setitem4 (mag use only)
} NO_ALIGN ITEM;


/* Bank Item Structure */

typedef struct st_bank_item {
  uint8_t data[12]; // the standard $setitem1 - $setitem3 fare
  uint32_t itemid; // player item id
  uint8_t data2[4]; // $setitem4 (mag use only)
  uint32_t bank_count; // Why?
} NO_ALIGN BANK_ITEM;

/* Bank Structure */

typedef struct st_bank {
  uint32_t bankUse;
  uint32_t bankMeseta;
  BANK_ITEM bankInventory [200];
} NO_ALIGN BANK;


/* Item Structure (Includes Flags) */

typedef struct st_inventory_item {
  uint8_t in_use; // 0x01 = item slot in use, 0xFF00 = unused
  uint8_t reserved[3];
  uint32_t flags; // 8 = equipped
  ITEM item;
} NO_ALIGN INVENTORY_ITEM;


/* Game Inventory Item Structure */

typedef struct st_game_item {
  uint32_t gm_flag; // reserved
  ITEM item;
} NO_ALIGN GAME_ITEM;


/* Main Character Structure */

typedef struct st_chardata {
  uint16_t packetSize; // 0x00-0x01  // Always set to 0x399C
  uint16_t command; // 0x02-0x03 // // Always set to 0x00E7
  uint8_t flags[4]; // 0x04-0x07
  uint8_t inventoryUse; // 0x08
  uint8_t HPmat; // 0x09
  uint8_t TPmat; // 0x0A
  uint8_t lang; // 0x0B
  INVENTORY_ITEM inventory[30]; // 0x0C-0x353
  uint16_t ATP; // 0x354-0x355
  uint16_t MST; // 0x356-0x357
  uint16_t EVP; // 0x358-0x359
  uint16_t HP; // 0x35A-0x35B
  uint16_t DFP; // 0x35C-0x35D
  uint16_t ATA; // 0x35E-0x35F
  uint16_t LCK; // 0x360-0x361
  uint8_t unknown[10]; // 0x362-0x36B
  uint16_t level; // 0x36C-0x36D;
  uint16_t unknown2; // 0x36E-0x36F;
  uint32_t XP; // 0x370-0x373
  uint32_t meseta; // 0x374-0x377;
  int8_t gcString[10]; // 0x378-0x381;
  uint8_t unknown3[14]; // 0x382-0x38F;  // Same as E5 unknown2
  uint8_t nameColorBlue; // 0x390;
  uint8_t nameColorGreen; // 0x391;
  uint8_t nameColorRed; // 0x392;
  uint8_t nameColorTransparency; // 0x393;
  uint16_t skinID; // 0x394-0x395;
  uint8_t unknown4[18]; // 0x396-0x3A7
  uint8_t sectionID; // 0x3A8;
  uint8_t _class; // 0x3A9;
  uint8_t skinFlag; // 0x3AA;
  uint8_t unknown5[5]; // 0x3AB-0x3AF;  // Same as E5 unknown4.
  uint16_t costume; // 0x3B0 - 0x3B1;
  uint16_t skin; // 0x3B2 - 0x3B3;
  uint16_t face; // 0x3B4 - 0x3B5;
  uint16_t head; // 0x3B6 - 0x3B7;
  uint16_t hair; // 0x3B8 - 0x3B9;
  uint16_t hairColorRed; // 0x3BA-0x3BB;
  uint16_t hairColorBlue; // 0x3BC-0x3BD;
  uint16_t hairColorGreen; // 0x3BE-0x3BF;
  uint32_t proportionX; // 0x3C0-0x3C3;
  uint32_t proportionY; // 0x3C4-0x3C7;
  uint8_t name[24]; // 0x3C8-0x3DF;
  uint32_t playTime; // 0x3E0 - 0x3E3;
  uint8_t unknown6[4];  // 0x3E4 - 0x3E7
  uint8_t keyConfig[232]; // 0x3E8 - 0x4CF;
  // Stored from ED 07 packet.
  uint8_t techniques[20]; // 0x4D0 - 0x4E3;
  uint8_t unknown7[16]; // 0x4E4 - 0x4F3;
  uint8_t options[4]; // 0x4F4-0x4F7;
  // Stored from ED 01 packet.
  uint32_t reserved4; // not sure
  uint8_t quest_data1[512]; // 0x4FC - 0x6FB; (Quest data 1)
  uint32_t reserved5;
  uint32_t bankUse; // 0x700 - 0x703
  uint32_t bankMeseta; // 0x704 - 0x707;
  BANK_ITEM bankInventory [200]; // 0x708 - 0x19C7
  uint32_t guildCard; // 0x19C8-0x19CB;
  // Stored from E8 06 packet.
  uint8_t name2[24]; // 0x19CC - 0x19E3;
  uint8_t unknown9[56]; // 0x19E4-0x1A1B;
  uint8_t guildcard_text[176]; // 0x1A1C - 0x1ACB
  uint8_t reserved1;  // 0x1ACC; // Has value 0x01 on Schthack's
  uint8_t reserved2; // 0x1ACD; // Has value 0x01 on Schthack's
  uint8_t sectionID2; // 0x1ACE;
  uint8_t _class2; // 0x1ACF;
  uint8_t unknown10[4]; // 0x1AD0-0x1AD3;
  uint8_t symbol_chats[1248]; // 0x1AD4 - 0x1FB3
  // Stored from ED 02 packet.
  uint8_t shortcuts[2624];  // 0x1FB4 - 0x29F3
  // Stored from ED 03 packet.
  uint8_t autoReply[344]; // 0x29F4 - 0x2B4B;
  uint8_t GCBoard[172]; // 0x2B4C - 0x2BF7;
  uint8_t unknown12[200]; // 0x2BF8 - 0x2CBF;
  uint8_t challengeData[320]; // 0x2CC0 - 0X2DFF
  uint8_t techConfig[40]; // 0x2E00 - 0x2E27
  uint8_t unknown13[40]; // 0x2E28-0x2E4F
  uint8_t quest_data2[92]; // 0x2E50 - 0x2EAB (Quest data 2)
  uint8_t unknown14[276]; // 0x2EAC - 0x2FBF; // I don't know what this is, but split from unknown13 because this chunk is
  // actually copied into the 0xE2 packet during login @ 0x08
  uint8_t keyConfigGlobal[364]; // 0x2FC0 - 0x312B  // Copied into 0xE2 login packet @ 0x11C
  // Stored from ED 04 packet.
  uint8_t joyConfigGlobal[56]; // 0x312C - 0x3163 // Copied into 0xE2 login packet @ 0x288
  // Stored from ED 05 packet.
  uint32_t guildCard2; // 0x3164 - 0x3167 (From here on copied into 0xE2 login packet @ 0x2C0...)
  uint32_t teamID; // 0x3168 - 0x316B
  uint8_t teamInformation[8]; // 0x316C - 0x3173 (usually blank...)
  uint16_t privilegeLevel; // 0x3174 - 0x3175
  uint16_t reserved3; // 0x3176 - 0x3177
  uint8_t teamName[28]; // 0x3178 - 0x3193
  uint32_t unknown15; // 0x3194 - 0x3197
  uint8_t teamFlag[2048]; // 0x3198 - 0x3997
  uint8_t teamRewards[8]; // 0x3998 - 0x39A0
} NO_ALIGN CHARDATA;


/* Connected Client Structure */

typedef struct st_banana {
  int32_t plySockfd;
  int32_t block;
  uint8_t rcvbuf [TCP_BUFFER_SIZE];
  uint16_t rcvread;
  uint16_t expect;
  uint8_t decryptbuf [TCP_BUFFER_SIZE]; // Used when decrypting packets from the client...
  uint8_t sndbuf [TCP_BUFFER_SIZE];
  uint8_t encryptbuf [TCP_BUFFER_SIZE]; // Used when making packets to send to the client...
  uint8_t packet [TCP_BUFFER_SIZE];
  int32_t snddata,
    sndwritten;
  int32_t crypt_on;
  PSO_CRYPT server_cipher, client_cipher;
  CHARDATA character;
  uint8_t equip_flags;
  uint32_t matuse[5];
  int32_t mode; // Usually set to 0, but changes during challenge and battle play
  void* character_backup; // regular character copied here during challenge and battle
  int32_t gotchardata;
  uint32_t guildcard;
  uint32_t temp_guildcard;
  int64_t hwinfo;
  int32_t isgm;
  int32_t slotnum;
  uint32_t response;    // Last time client responded...
  uint32_t lastTick;    // The last second
  uint32_t toBytesSec;  // How many bytes per second the server sends to the client
  uint32_t fromBytesSec;  // How many bytes per second the server receives from the client
  uint32_t packetsSec;  // How many packets per second the server receives from the client
  uint8_t sendCheck[MAX_SENDCHECK+2];
  uint8_t preferred_lobby;
  uint16_t lobbyNum;
  uint8_t clientID;
  int32_t bursting;
  int32_t teamaccept;
  int32_t masterxfer;
  int32_t todc;
  uint32_t dc_time;
  uint8_t IP_Address[16]; // Text version
  uint8_t ipaddr[4]; // Binary version
  uint32_t connected;
  uint32_t savetime;
  uint32_t connection_index;
  uint32_t drop_area;
  int64_t drop_coords;
  uint32_t drop_item;
  int32_t released;
  uint8_t releaseIP[4];
  uint16_t releasePort;
  int32_t sending_quest;
  uint32_t qpos;
  int32_t hasquest;
  int32_t doneshop[3];
  int32_t dead;
  int32_t lobbyOK;
  uint32_t ignore_list[100];
  uint32_t ignore_count;
  INVENTORY_ITEM tekked;
  uint32_t team_info_flag, team_info_request;
  uint32_t command_cooldown[256];
  uint32_t team_cooldown[32];
  int32_t bankType;
  int32_t bankAccess;
  BANK common_bank;
  BANK char_bank;
  void* lobby;
  int32_t announce;
  int32_t debugged;
} BANANA;


/* Quest Details Structure */

typedef struct st_qdetails {
  uint16_t qname[32];
  uint16_t qsummary[128];
  uint16_t qdetails[256];
  uint8_t* qdata;
  uint32_t qsize;
} QDETAILS;

/* Loaded Quest Structure */

typedef struct st_quest {
  QDETAILS* ql[10];  // Supporting 10 languages
  uint8_t* mapdata;
  uint32_t max_objects;
  uint8_t* objectdata;
} QUEST;


/* Assembled Quest Menu Structure */

typedef struct st_questmenu {
  uint32_t num_categories;
  uint8_t c_names[10][256];
  uint8_t c_desc[10][256];
  uint32_t quest_counts[10];
  uint32_t quest_indexes[10][32];
} QUEST_MENU;


/* a RC4 expanded key session */

const uint8_t RC4publicKey[32] = {
  103, 196, 247, 176, 71, 167, 89, 233, 200, 100, 044, 209, 190, 231, 83, 42,
  6, 95, 151, 28, 140, 243, 130, 61, 107, 234, 243, 172, 77, 24, 229, 156
};

struct rc4_key {
    uint8_t state[256];
    uint32_t x, y;
};


/* Connected Logon Server Structure */

typedef struct st_orange {
  int32_t sockfd;
  struct in_addr _ip;
  uint8_t rcvbuf [TCP_BUFFER_SIZE];
  uint32_t rcvread;
  uint32_t expect;
  uint8_t decryptbuf [TCP_BUFFER_SIZE];
  uint8_t sndbuf [PACKET_BUFFER_SIZE];
  uint8_t encryptbuf [TCP_BUFFER_SIZE];
  int32_t snddata, sndwritten;
  uint8_t packet [PACKET_BUFFER_SIZE];
  uint32_t packetdata;
  uint32_t packetread;
  int32_t crypt_on;
  uint8_t user_key[128];
  int32_t key_change[128];
  struct rc4_key cs_key;
  struct rc4_key sc_key;
  uint32_t last_ping;
} ORANGE;


/* Ship List Structure (Assembled from Logon Packet) */

typedef struct st_shiplist {
  uint32_t shipID;
  uint8_t ipaddr[4];
  uint16_t port;
} SHIPLIST;


/* Shop Item Structure */

typedef struct st_shopitem {
  uint8_t data[12];
  uint32_t reserved3;
  uint32_t price;
} NO_ALIGN SHOP_ITEM;


/* Shop Structure */

typedef struct st_shop {
  uint16_t packet_length;
  uint16_t command;
  uint32_t flags;
  uint32_t reserved;
  uint8_t type;
  uint8_t num_items;
  uint16_t reserved2;
  SHOP_ITEM item[0x18];
  uint8_t reserved4[16];
} NO_ALIGN SHOP;


/* Map Monster Structure */

typedef struct st_mapmonster {
  uint32_t base;  // 4
  uint32_t reserved[11]; // 44
  float reserved11; // 4
  float reserved12; // 4
  uint32_t reserved13; // 4
  uint32_t exp; // 4
  uint32_t skin; // 4
  uint32_t rt_index;  // 4
} NO_ALIGN MAP_MONSTER;


/* Map box structure */

typedef struct st_mapbox {
  float flag1;
  float flag2;
  float flag3;
  uint8_t drop[8];
} MAP_BOX;


/* Internal Monster Structure */

typedef struct st_monster {
  int16_t HP;
  uint32_t dead[4];
  uint32_t drop;
} MONSTER;


/* Lobby Structure */

typedef struct st_lobby {
  uint8_t floor[12];
  uint32_t clientx[12];
  uint32_t clienty[12];
  uint8_t arrow_color[12];
  uint32_t lobbyCount;
  MONSTER monsterData[0xB50];
  MAP_MONSTER mapData[0xB50]; // For figuring out which monsters go where, etc.
  MAP_BOX objData[0xB50]; // Box drop information
  uint32_t mapIndex;
  uint32_t objIndex;
  uint32_t rareIndex;
  uint8_t rareData[0x20];
  uint8_t boxHit[0xB50];
  GAME_ITEM gameItem[MAX_SAVED_ITEMS]; // Game Item Data
  uint32_t gameItemList[MAX_SAVED_ITEMS]; // Game Item Link List
  uint32_t gameItemCount;
  uint32_t itemID;
  uint32_t playerItemID[4];
  int32_t questE0; // Server already dropped BP reward?
  int32_t drops_disabled; // Basically checks if someone exchanged a photon crystal
  uint32_t bankItemID[4];
  uint32_t leader;
  uint8_t sectionID;
  uint32_t gamePlayerCount; // This number increases as people join and depart the game...
  uint32_t gamePlayerID[4]; // Keep track for leader purposes...
  uint8_t gameName[30];
  uint8_t gamePassword[32];
  uint8_t gameMap[128];
  uint8_t gameMonster[0x04];
  uint8_t episode;
  uint8_t difficulty;
  uint8_t battle;
  uint8_t challenge;
  uint8_t oneperson;
  uint16_t battle_level;
  int32_t meseta_boost;
  int32_t quest_in_progress;
  int32_t quest_loaded;
  int32_t inpquest;
  uint32_t start_time;
  int32_t in_use;
  int32_t redbox;
  int32_t slot_use[12];
  BANANA* client[12];
  BATTLEPARAM* bptable;
} LOBBY;


/* Block Structure */

typedef struct st_block {
  LOBBY lobbies[16+SHIP_COMPILED_MAX_GAMES];
  uint32_t count; // keep track of how many people are on this block
} BLOCK;
