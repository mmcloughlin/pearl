#include <stdio.h>
#include <inttypes.h>

#include "crypto.h"

void print_bytes(char *data, int n)
{
  for(int i = 0; i < n; i++) {
    printf("%02x", (uint8_t)data[i]);
    if(i%16 == 15) {
      printf("\n");
    }
  }
}

int main(int argc, char **argv)
{
  char data1[1024], data2[1024], data3[1024];

  crypto_rand(data1, 1024);
  memset(data2, 0, 1024);
  memset(data3, 0, 1024);

  print_bytes(data1, 1024);

  //crypto_pk_obsolete_public_hybrid_encrypt();
}
