#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static u_char xor[12];
static u_char perm[12];
static void
getrnd ()
{
  struct timeval s;
  u_int *ptr;
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd > 0)
    {
      if(read (fd, xor, 12) < 0) exit(-1);
      if(read (fd, perm, 12) < 0) exit(-1);
      close (fd);
      return;
    }

  gettimeofday (&s, 0);
  srand (s.tv_usec);
  ptr = (u_int *) xor;
  *ptr = rand ();
  *(ptr + 1) = rand ();
  *(ptr + 2) = rand ();
  ptr = (u_int *) perm;
  *ptr = rand ();
  *(ptr + 1) = rand ();
  *(ptr + 2) = rand ();


}
void
init_hash ()
{
  int i, n, j;
  int p[12];
  getrnd ();
  for (i = 0; i < 12; i++)
    p[i] = i;
  for (i = 0; i < 12; i++)
    {
      n = perm[i] % (12 - i);
      perm[i] = p[n];
      for (j = 0; j < 11 - n; j++)
	p[n + j] = p[n + j + 1];
    }
}

u_int mkhash (u_int src, u_short sport, u_int dest, u_short dport)
{
	u_int res = 0;
	int i;
	u_char data[12];
	
	memcpy(data, &src, sizeof src);
	memcpy(data + 4, &dest, sizeof dest);
	memcpy(data + 8, &sport, sizeof sport);
	memcpy(data + 10, &dport, sizeof dport);
	for (i = 0; i < 12; i++)
		res = ( (res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
	return res;
}
