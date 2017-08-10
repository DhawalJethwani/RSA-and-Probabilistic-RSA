#include <iostream>
#include <time.h>
#include <gmp.h>
#include <stdlib.h>

using namespace std;

#define N_BIT_SIZE 1024
#define N_HEX_SIZE (N_BIT_SIZE/8)
#define PRIME_HEX_SIZE ((N_BIT_SIZE/8)/2)
#define PUB_EXP 3

struct public_key
{
  mpz_t n;
  mpz_t e;
}typedef pub_key;

struct private_key
{
  mpz_t n;
  mpz_t e;
  mpz_t d;
  mpz_t p;
  mpz_t q;
}typedef prv_key;

void define_keys(pub_key *pubk, prv_key *prvk)
{
  char buf[PRIME_HEX_SIZE];
  mpz_t totient; mpz_init(totient);
  mpz_t t1; mpz_init(t1);
  mpz_t t2; mpz_init(t2);

  srand(time(NULL));

  mpz_init_set_ui (pubk->e,PUB_EXP);
  mpz_init_set_ui (prvk->e,PUB_EXP);

  for(int i = 0 ; i < PRIME_HEX_SIZE ; i++)
  {
    buf[i]=rand()%255;
  }
  buf[0] |= 192;
  buf[PRIME_HEX_SIZE - 1] |= 1;

  mpz_import (t1,PRIME_HEX_SIZE,1,sizeof(buf[0]),0,0,buf);

  mpz_nextprime(prvk->p,t1);
  mpz_mod(t2,prvk->p,pubk->e);
  while(!mpz_cmp_ui(t2,1))
  {
      mpz_nextprime(prvk->p,prvk->p);
      mpz_mod(t2,prvk->p,prvk->e);
  }

  mpz_init_set(prvk->q,prvk->p);
  while(mpz_cmp(prvk->p,prvk->q) == 0)
  {
    for (int i = 0 ; i < PRIME_HEX_SIZE ; i++)
    {
      buf[i] = rand() % 255;
    }
    buf[0]|=192;
    buf[PRIME_HEX_SIZE-1]|=1;
    mpz_import(t1,PRIME_HEX_SIZE,1,sizeof(buf[0]),0,0,buf);
    mpz_nextprime(prvk->q,t1);
    mpz_mod(t2,prvk->q,pubk->e);
    while(!mpz_cmp_ui(t2, 1))
    {
      mpz_nextprime(prvk->q,prvk->q);
      mpz_mod(t2,prvk->q,pubk->e);
    }
  }
  mpz_mul(pubk->n,prvk->p,prvk->q);
  mpz_init_set (prvk->n,pubk->n);
  mpz_sub_ui(t1,prvk->p,1);
  mpz_sub_ui(t2,prvk->q,1);
  mpz_mul(totient,t1,t2);
  mpz_invert(prvk->d, pubk->e, totient);
  return;
}

void block_encrypt(mpz_t C, mpz_t M, public_key pubk)
{
    mpz_powm(C, M, pubk.e, pubk.n);
    return;
}

void block_decrypt(mpz_t M, mpz_t C, private_key prvk)
{
    mpz_powm(M, C, prvk.d, prvk.n);
    return;
}

int main()
{
  int i;
  mpz_t M;  mpz_init(M);
  mpz_t C;  mpz_init(C);
  mpz_t DC;  mpz_init(DC);
  private_key prvk;
  public_key pubk;

  mpz_init(pubk.n);
  mpz_init(pubk.e);

  mpz_init(prvk.n);
  mpz_init(prvk.e);
  mpz_init(prvk.d);
  mpz_init(prvk.p);
  mpz_init(prvk.q);

  define_keys(&pubk, &prvk);
  cout << "---------------Private Key-----------------" << "\n";
  cout << "n is " << mpz_get_str(NULL, 16, pubk.n) << "\n";
  cout << "e is " << mpz_get_str(NULL, 16, pubk.e) << "\n";
  cout << "\n\n";
  cout << "---------------Public Key------------------" << "\n";
  cout << "n is " << mpz_get_str(NULL, 16, prvk.n) << "\n";
  cout << "e is " << mpz_get_str(NULL, 16, prvk.e) << "\n";
  cout << "d is " << mpz_get_str(NULL, 16, prvk.d) << "\n";
  cout << "p is " << mpz_get_str(NULL, 16, prvk.p) << "\n";
  cout << "q is " << mpz_get_str(NULL, 16, prvk.q) << "\n";

  char buf[N_HEX_SIZE];
  for(i = 0; i < N_HEX_SIZE; i++)
  {
      buf[i] = rand() % 255;
  }
  mpz_import(M, (N_HEX_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
  cout << "Oiginal Message is " << mpz_get_str(NULL, 16, M) << "\n";
  block_encrypt(C, M, pubk);
  cout << "Encrypted Message is " << mpz_get_str(NULL, 16, C) << "\n";
  block_decrypt(DC, C, prvk);
  cout << "Decrypted Message is " << mpz_get_str(NULL, 16, DC) << "\n";
  return 0;
}
