

#include "sha3.h"

#include <ctype.h>

char *text[] =
{ "",
  "a",
  "abc",
  "message digest",
  "abcdefghijklmnopqrstuvwxyz",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
};

char *sha3_dgst[] =
{ "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
  "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd",
  "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521",
  "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f",
  "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d"
};

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
} 

int run_tests (void)
{
  uint8_t  dgst[256], tv[256];
  int      i, fails=0;
  SHA3_CTX ctx;
  
  for (i=0; i<sizeof(text)/sizeof(char*); i++)
  {
    SHA3_Init (&ctx, SHA3_256);
    SHA3_Update (&ctx, text[i], strlen (text[i]));
    SHA3_Final (dgst, &ctx);
    
    hex2bin (tv, sha3_dgst[i]);
    
    if (memcmp (dgst, tv, ctx.dgstlen) != 0) {
      printf ("\nFailed for string \"%s\"", text[i]);
      ++fails;
    }
  }
  return fails;
}

void sha3_string (char hdr[], void *data, size_t len, int type)
{
  SHA3_CTX ctx;
  size_t   i;
  uint8_t  dgst[256];
  uint8_t *p=(uint8_t*)data;

  printf ("\n%s(\"%s\")\n0x", hdr, p);
  
  SHA3_Init (&ctx, type);
  SHA3_Update (&ctx, p, len);
  SHA3_Final (dgst, &ctx);
  
  for (i=0; i<ctx.dgstlen; i++) {
    printf ("%02x", dgst[i]);
  }
  putchar ('\n');
}

int main (int argc, char *argv[])
{
  int i, fails;
  char *hdrs[]={"SHA3-224","SHA3-256","SHA3-384","SHA3-512"};

  if (argc < 2) {
    if (!(fails=run_tests())) {
      printf ("\nSelf-test OK!");
    } else {
      printf ("\nSelf-test failed with %i errors", fails);
    }
    return 0;
  }
  for (i=0; i<4; i++) {
    sha3_string (hdrs[i], argv[1], strlen (argv[1]), i);
  }
  return 0;
}
