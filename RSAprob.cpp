#include <iostream>
#include <time.h>
#include <gmp.h>
#include <stdlib.h>

using namespace std;

#define N_BIT_SIZE 2048
#define PUB_EXP 65537

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
  mpz_t r;
  mpz_t t;
  mpz_t h;
  mpz_t p;
  mpz_t q;
  mpz_t m;
  mpz_t phi;
}typedef prv_key;

void generator_elem(mpz_t g, mpz_t order, mpz_t phi_n, mpz_t n)
{
  mpz_t temp,tg,pow_g;
  mpz_init(tg);
  mpz_init(temp);
  mpz_init(pow_g);
  mpz_set_ui(tg,2);
  mpz_cdiv_q(pow_g,phi_n,order);
  while(true)
  {
    mpz_powm(temp,tg,pow_g,n);
    if(mpz_cmp_ui(temp,1)!=0)
    {
      break;
    }
    mpz_add_ui(tg,tg,1);
  }
  mpz_set(g,temp);
  return;
}

void rand_gen(mpz_t x,int bit_size)
{
  int byte_size=bit_size/8;
  char buf[byte_size];
  srand(time(NULL));
  for(int i=0;i<byte_size;i++)
  {
    buf[i]=rand()%255;
  }
  buf[0] |= 192;
  buf[byte_size - 1] |= 1;
  mpz_import (x,byte_size,1,sizeof(buf[0]),0,0,buf);
}

void find_prime(mpz_t x,int bit_size)
{
  rand_gen(x,bit_size);
  mpz_nextprime(x,x);
}

void define_keys(pub_key *pubk, prv_key *prvk)
{
  mpz_t totient; mpz_init(totient);
  mpz_t temp; mpz_init(temp);
  mpz_init_set_ui (pubk->e,PUB_EXP);
  mpz_init_set_ui (prvk->e,PUB_EXP);

  find_prime(prvk->r,N_BIT_SIZE/4);

  int i=0;
  do{
    find_prime(prvk->t,N_BIT_SIZE/4);
  }while(mpz_cmp(prvk->r,prvk->t) == 0);

  mpz_mul_ui(temp,prvk->r,2);
  do{
    rand_gen(prvk->p,N_BIT_SIZE/4);
    mpz_mul(prvk->p,prvk->p,temp);
    mpz_add_ui(prvk->p,prvk->p,1);
  }while(mpz_probab_prime_p(prvk->p,35) == 0);

  mpz_mul_ui(temp,prvk->t,2);
  do{
       rand_gen(prvk->q,N_BIT_SIZE/4);
       mpz_mul(prvk->q,prvk->q,temp);
       mpz_add_ui(prvk->q,prvk->q,1);
  }while(mpz_probab_prime_p(prvk->q,35) == 0);

  mpz_mul(prvk->n,prvk->p,prvk->q);
  mpz_set(pubk->n,prvk->n);

  mpz_mul(temp,prvk->t,prvk->e);
  mpz_invert(prvk->d,temp,prvk->r);
  mpz_mul(prvk->d,prvk->d,prvk->t);

  mpz_sub_ui(temp,prvk->p,1);
  mpz_set(prvk->phi,temp);
  mpz_sub_ui(temp,prvk->q,1);
  mpz_mul(prvk->phi,prvk->phi,temp);

  generator_elem(prvk->h,prvk->t,prvk->phi,prvk->n);
  generator_elem(prvk->m,prvk->r,prvk->phi,prvk->n);

  mpz_clear(temp);
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
  mpz_init(prvk.r);
  mpz_init(prvk.t);
  mpz_init(prvk.h);
  mpz_init(prvk.phi);
  mpz_init(prvk.m);
  cout << "dgr";
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
  cout << "r is " << mpz_get_str(NULL, 16, prvk.r) << "\n";
  cout << "t is " << mpz_get_str(NULL, 16, prvk.t) << "\n";
  cout << "h is " << mpz_get_str(NULL, 16, prvk.h) << "\n";
  cout << "phi is " << mpz_get_str(NULL, 16, prvk.phi) << "\n";

  /*mpz_set(M,prvk.m);
  cout << "Oiginal Message is " << mpz_get_str(NULL, 16, M) << "\n";
  block_encrypt(C, M, pubk);
  cout << "Encrypted Message is " << mpz_get_str(NULL, 16, C) << "\n";
  block_decrypt(DC, C, prvk);
  cout << "Decrypted Message is " << mpz_get_str(NULL, 16, DC) << "\n";*/
  return 0;
}
