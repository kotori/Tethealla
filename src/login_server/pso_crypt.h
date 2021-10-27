#ifndef _PSO_CRYPT_H_
#define _PSO_CRYPT_H_

#define TABLE_SIZE (1024 + 18)

#define PSO_CRYPT_TYPE_DC 0
#define PSO_CRYPT_TYPE_GC 1
#define PSO_CRYPT_TYPE_BB 2

typedef struct pso_crypt {
  uint32_t tbl[TABLE_SIZE];
  int32_t type;
  int32_t cur;
  int32_t size;
  void (*mangle)(struct pso_crypt *);
} PSO_CRYPT;

/* for DC */
void pso_crypt_table_init_dc(PSO_CRYPT *pcry, const uint8_t *salt);

/* for GC */
void pso_crypt_table_init_gc(PSO_CRYPT *pcry, const uint8_t *salt);

/* for BB */
void pso_crypt_table_init_bb(PSO_CRYPT *pcry, const uint8_t *salt);
void pso_crypt_decrypt_bb(PSO_CRYPT *pcry, uint8_t *data, unsigned
  length);
void pso_crypt_encrypt_bb(PSO_CRYPT *pcry, uint8_t *data, unsigned
  length);

/* common */
void pso_crypt_init(PSO_CRYPT *pcry, const uint8_t *salt, int32_t type);
void pso_crypt(PSO_CRYPT *pcry, uint8_t *data, int32_t len, int32_t enc);
uint32_t pso_crypt_get_num(PSO_CRYPT *pcry);

#endif /* _PSO_CRYPT_H_ */
