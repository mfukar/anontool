#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16

typedef unsigned char  UINT8;
typedef unsigned int   UINT32;
typedef unsigned short UINT16;

// Error codes
#define RIJNDAEL_SUCCESS 0
#define RIJNDAEL_UNSUPPORTED_MODE -1
#define RIJNDAEL_UNSUPPORTED_DIRECTION -2
#define RIJNDAEL_UNSUPPORTED_KEY_LENGTH -3
#define RIJNDAEL_BAD_KEY -4
#define RIJNDAEL_NOT_INITIALIZED -5
#define RIJNDAEL_BAD_DIRECTION -6
#define RIJNDAEL_CORRUPTED_DATA -7

typedef enum { Encrypt , Decrypt } Direction;
typedef enum { ECB , CBC , CFB1 } Mode;
typedef enum { Key16Bytes , Key24Bytes , Key32Bytes } KeyLength;
typedef enum { Valid , Invalid } State;

int init(Mode mode,Direction dir,const UINT8 *key,KeyLength keyLen,UINT8 * initVector);
int blockEncrypt(const UINT8 *input, int inputLen, UINT8 *outBuffer);
int padEncrypt(const UINT8 *input, int inputOctets, UINT8 *outBuffer);
int blockDecrypt(const UINT8 *input, int inputLen, UINT8 *outBuffer);
int padDecrypt(const UINT8 *input, int inputOctets, UINT8 *outBuffer);
void keySched(UINT8 key[_MAX_KEY_COLUMNS][4]);
void keyEncToDec();
void encrypt(const UINT8 a[16], UINT8 b[16]);
void decrypt(const UINT8 a[16], UINT8 b[16]);
UINT32 anonymize( const UINT32 orig_addr);
void PAnonymizer(const UINT8 * key);
