/*
 * Shark Cypher (sharcy)
 *
 * uses Volume Gamma by Alex Tikhonov with great avalanche and diffusion, 2008
 *
 * Copyright (C) 2008, 2009 Alex Tikhonov     tikhonov.alex@gmail.com
 *
 * Released under the terms of the GNU GPL v2.0.
 *
 * bugreport, support, adaptation: tikhonov.alex@gmail.com
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/timeb.h>
#include <sys/sysinfo.h>
//#include <unistd.h>

uint64_t NearestPow2(uint64_t x)
{
 x = x - 1;
 x = x | (x>>1);
 x = x | (x>>2);
 x = x | (x>>4);
 x = x | (x>>8);
 x = x | (x>>16);
 x = x | (x>>32);
 //x = x | (x>>64);
 x = x + 1;
 if(x < 1<<7)
   x = 1<<7;
 return x;
}

static __inline__ uint64_t swab64(uint64_t x)
{
 return x<<56 | x>>56 |
        (x & (uint64_t)0x000000000000ff00ULL)<<40 |
        (x & (uint64_t)0x0000000000ff0000ULL)<<24 |
        (x & (uint64_t)0x00000000ff000000ULL)<< 8 |
        (x & (uint64_t)0x000000ff00000000ULL)>> 8 |
        (x & (uint64_t)0x0000ff0000000000ULL)>>24 |
        (x & (uint64_t)0x00ff000000000000ULL)>>40;
}

#define GetBit(x) (((tData)[x>>3]&(128>>(x%8)))!=0)
#define SetBit(x) ((TmpData)[(x)>>3]|=(128>>((x)%8)))

uint8_t ConTable[4] = {2,3,1,0};
uint8_t BitConTable[2][2] = {{2,3},{1,0}};  // Good Enthropy
////////uint8_t BitConTable[2][2] = {{0,1},{3,2}};  // Normal

uint8_t BitRevTable[2][2] = {{3,2},{0,1}};
//uint8_t BitConTable[4][2] = {{0,1},{1,1},{0,1},{0,0}};
//uint8_t BitRevTable[4][2] = {{1,1},{1,0},{0,0},{0,1}};

uint8_t *Data = NULL;
uint64_t DataLen = 0;
uint8_t *Key = NULL;
uint64_t KeyLen = 0;
uint64_t BSize = 0;

timeb tBeg, tEnd;

int DevRandom = 0;
bool LittleEndian;
bool Encrypt = true;
bool Random = false;
int Verbose = 0;

unsigned long RAMount;

bool IsLittleEndian(void)
{
 uint16_t t16 = 0xff;
 uint8_t *t8 = (uint8_t*) &t16;
 if(*t8)
   return true;
 else
   return false;
}

int SharcyEncrypt(uint8_t **_Data, uint64_t &_DataLen, uint8_t *_Key, uint64_t _KeyLen)
{
 if(_Data==NULL || *_Data==NULL || _Key==NULL){
  fprintf(stderr, "Not initialized data!\n");
  return 0;
 }
 if(_DataLen==0 || _KeyLen==0){
  fprintf(stderr, "Empty data!\n");
  return 0;
 }

 if(Random){
   FILE *f = fopen("SourceFile.dat", "w");
   if(!f){
     fprintf(stderr, "*Error* Can't open file \"SourceFile.dat\"\n");
   }
   fwrite(_Data, _DataLen, 1, f);
   fclose(f);
 }

 uint8_t *tData = (uint8_t*) malloc(_DataLen);
 for(uint64_t q=0; q<_DataLen; q++)
    tData[q] = (*_Data)[q];

 uint64_t ResDataLen = _DataLen;

 _DataLen += sizeof(uint64_t);
 
 uint64_t Log2;
 int64_t KeyP = 0;
 uint64_t bDataLen;

 uint64_t OldDataLen = _DataLen;
 if(_DataLen < _KeyLen)
   _DataLen = _KeyLen;
 _DataLen = NearestPow2(_DataLen + (_DataLen%sizeof(uint64_t)) + sizeof(uint64_t));
 bDataLen = _DataLen << 3;
 tData = (uint8_t*) realloc(tData, _DataLen);
 uint8_t *TmpData = (uint8_t*) malloc(_DataLen);

 if(!DevRandom)
   for(uint64_t i=OldDataLen; i<_DataLen; i++)
     tData[i] = (uint8_t) (256 * random() / RAND_MAX);
 else {
   FILE *fR;
   if(DevRandom == 1)
     fR = fopen("/dev/urandom", "r");
   else
     fR = fopen("/dev/random", "r");
   if(!fR){
     fprintf(stderr, "*Error* Can't open /dev/random\n");
     exit(11);
   }
   if(Verbose)
     printf("Reading random data. Please Be Patient.\n");
   for(uint64_t i=OldDataLen; i<_DataLen; i++){
     fread(&tData[i], 1, 1, fR);
   }
   fclose(fR);
 }

 if(Verbose>1)
   printf("<%lu>", ResDataLen);

 // add noise to data' lenght for security purposes
 for(uint64_t noise=_DataLen<<1; noise; noise<<=1)
   if(random()%2)
     ResDataLen |= noise;

 if(LittleEndian)
   ((uint64_t*)&tData[_DataLen-sizeof(uint64_t)])[0] = swab64(ResDataLen);
 else
   ((uint64_t*)&tData[_DataLen-sizeof(uint64_t)])[0] = ResDataLen;

 Log2 = 1;
 for(; Log2<=255; Log2++)
   if(_DataLen & (1<<Log2))
     break;
 Log2 += 3;

 for(uint64_t i=2; i<=bDataLen; i*=2)
   {
    for(uint64_t q=0; q<_DataLen; q++)
       TmpData[q] = 0;

    for(uint64_t g=0; g<_DataLen; g++){
       tData[g] ^= Key[KeyP++];
       if(KeyP >= _KeyLen)
       KeyP = 0;
    }
    for(uint64_t j=0; j<bDataLen; j+=i){
       uint64_t l = j;
       for(uint64_t k=j; k<j+i/2; k++, l+=2){
          uint8_t a1 = (tData[(k)>>3] & (128>>((k)%8))) != 0;
          uint8_t a2 = (tData[(k+i/2)>>3] & (128>>((k+i/2)%8))) != 0;
          uint8_t a = BitConTable[a1][a2];
          if((a&2)!=0)
            SetBit(l);
          if((a2&1)!=0)
            SetBit(l+1);
       }
    }

    uint8_t *Swp = tData;
    tData = TmpData;
    TmpData = Swp;
   }

 if(Random){
   FILE *f = fopen("DestinationFile.dat", "w");
   if(!f){
     fprintf(stderr, "*Error* Can't open file \"DestinationFile.dat\"\n");
   }
   fwrite(tData, _DataLen, 1, f);
   fclose(f);
 }

 *_Data = (uint8_t*) realloc(*_Data, _DataLen);
 for(uint64_t q=0; q<_DataLen; q++)
    (*_Data)[q] = tData[q];

 free(tData);
 free(TmpData);
 return _DataLen;
}

int SharcyDecrypt(uint8_t **_Data, uint64_t &_DataLen, uint8_t *_Key, uint64_t _KeyLen)
{
 if(_Data==NULL || *_Data==NULL || _Key==NULL){
  fprintf(stderr, "Not initialized data!\n");
  return 0;
 }
 if(_DataLen==0 || _KeyLen==0){
  fprintf(stderr, "Empty data!\n");
  return 0;
 }

 uint8_t *tData = (uint8_t*) malloc(_DataLen);
 uint8_t *TmpData = (uint8_t*) malloc(_DataLen);
 for(uint64_t q=0; q<_DataLen; q++)
    tData[q] = (*_Data)[q];

 uint64_t Log2;
 int64_t KeyP = 0;
 uint64_t  bDataLen = _DataLen << 3;

 Log2 = 1;
 for(; Log2<=255; Log2++)
   if(_DataLen & (1<<Log2))
     break;
 Log2 += 3;

 if(_KeyLen)
   KeyP = (DataLen*Log2) % _KeyLen;
 else
   KeyP = 0;

 for(uint64_t i=bDataLen; i>=2; i/=2){
    for(uint64_t q=0; q<_DataLen; q++)
       TmpData[q] = 0;
    for(uint64_t j=0; j<bDataLen; j+=i){
       uint64_t l = j;
       uint64_t k = j;
       for( l=j; l<j+i; l+=2, k++){
          uint8_t a1 = (tData[(l)>>3] & (128>>((l)%8))) != 0;
          uint8_t a2 = (tData[(l+1)>>3] & (128>>((l+1)%8))) != 0;
          uint8_t a = BitRevTable[a1][a2];
          if((a&2)!=0)
            SetBit(k);
          if((a2&1)!=0)
            SetBit(k+i/2);
       }
    }

    for(int64_t g=_DataLen-1; g>=0; g--){
       KeyP--;
       if(KeyP<0)
         KeyP = _KeyLen - 1;
       TmpData[g] ^= Key[KeyP];
    }

    uint8_t *Swp = tData;
    tData = TmpData;
    TmpData = Swp;
 }

 uint64_t CompDataLen = ((uint64_t*)&tData[_DataLen-sizeof(uint64_t)])[0];

 if(LittleEndian)
   CompDataLen = swab64(CompDataLen);

 // remove noise from data' lenght
 uint64_t denoise=_DataLen, noisec=_DataLen>>1;
 for(; noisec; noisec>>=1)
     denoise |= noisec;
 CompDataLen &= denoise;
 if(Verbose>1)
   printf("<%lu>", CompDataLen);

 if(Random){
   FILE *f = fopen("RestoredFile.dat", "w");
   if(!f){
     fprintf(stderr, "*Error* Can't open file \"RestoredFile.dat\"\n");
   }
   fwrite(tData, CompDataLen, 1, f);
   fclose(f);
 }

 for(uint64_t q=0; q<CompDataLen; q++)
    (*_Data)[q] = tData[q];
 free(tData);
 free(TmpData);
 _DataLen = CompDataLen;
 return _DataLen;
}

void RandomTest(void)
{
 printf("Random test running...\n");
 DataLen = 6000000;
 if(Data)
   free(Data);
 Data = (uint8_t*) malloc(DataLen);

 for(uint64_t i=0; i<DataLen; i++)
   Data[i] = (uint8_t) (256 * random() / RAND_MAX);

 KeyLen = 1024;
 if(Key)
   free(Key);
 Key = (uint8_t*) malloc(KeyLen);
 for(uint64_t i=0; i<KeyLen; i++)
    Key[i] = (uint8_t) (256 * random() / RAND_MAX);

 DataLen = SharcyEncrypt(&Data, DataLen, Key, KeyLen);
 free(Data);
 Data = NULL;
 free(Key);
 Key = NULL;
}

void EncryptFile(char *FileName)
{
 if(Verbose)
   printf("Encrypting file %s \n", FileName);
 FILE *Ff = fopen(FileName, "r");
 if(!Ff){
   fprintf(stderr, "*Error* Can't open file \"%s\"\n", FileName);
   return;
 }
 fseek(Ff, 0, SEEK_END);
 long fts = ftell(Ff);
 if(fts == -1)
   return;
 uint64_t FSize = fts;
 fseek(Ff, 0, SEEK_SET);

 char *OutFileName = (char*) malloc(strlen(FileName)+4);
 sprintf(OutFileName, "%s%s", FileName, ".scy");
 FILE *Of = fopen(OutFileName, "w");
 if(!Of){
   fprintf(stderr, "*Error* Can't create file \"%s\"\n", OutFileName);
   fclose(Ff);
   return;
 }

 ftime(&tBeg);
 if(BSize){
   BSize =  NearestPow2(BSize) - sizeof(uint64_t)*2;
   DataLen = BSize;
   if(DataLen > RAMount){
     printf("Block size may be too big for available memory!\nPress any key to continue or Ctrl-Break for cancel.\n");
     getchar();
   }
   Data = (uint8_t*) malloc(DataLen);
   uint64_t fl = fread(Data, 1, DataLen, Ff);
   while(fl){
     if(Verbose>1)
       printf("%lu->", fl);
     try {
       SharcyEncrypt(&Data, fl, Key, KeyLen);
     }
     catch(...){
       fprintf(stderr, "*Error* in Encrypt (may be wrong size of block\n)");
     }
     fwrite(Data, fl, 1, Of);
     if(Verbose>1)
       printf("%lu\n", fl);
     fl = fread(Data, 1, DataLen, Ff);
   }
 }
 else {
   DataLen = FSize;
   if(DataLen > RAMount){
     printf("File size too big for available memory!\nPress any key to continue or Ctrl-Break for cancel.\n");
     getchar();
   }
   Data = (uint8_t*) malloc(DataLen);
   fread(Data, DataLen, 1, Ff);
   try {
     SharcyEncrypt(&Data, DataLen, Key, KeyLen);
   }
   catch(...){
     fprintf(stderr, "*Error* in Encrypt (may be wrong size of block\n)");
   }
   fwrite(Data, DataLen, 1, Of);
 }
 ftime(&tEnd);
 fclose(Ff);
 fclose(Of);
 free(OutFileName);
 free(Data);
}

void DecryptFile(char *FileName)
{
 if(Verbose)
   printf("Decrypting file %s \n", FileName);
 FILE *Ff = fopen(FileName, "r");
 if(!Ff){
   fprintf(stderr, "*Error* Can't open file \"%s\"\n", FileName);
   return;
 }
 fseek(Ff, 0, SEEK_END);
 long fts =  ftell(Ff);
 if(fts == -1)
   return;
 uint64_t FSize = fts;
 fseek(Ff, 0, SEEK_SET);

 char *OutFileName = (char*) malloc(strlen(FileName)+6);
 if(strcasestr(FileName, ".scy") - FileName <4)
   sprintf(OutFileName, "%s%s", FileName, ".descy");
 else {
   sprintf(OutFileName, "%s", FileName);
   OutFileName[strlen(OutFileName)-4] = 0;
 }

 FILE *Of = fopen(OutFileName, "w");
 if(!Of){
   fprintf(stderr, "*Error* Can't create file \"%s\"\n", OutFileName);
   fclose(Ff);
   return;
 }

 ftime(&tBeg);
 if(BSize){
   BSize =  NearestPow2(NearestPow2(BSize)-sizeof(uint64_t));
   DataLen = BSize;
   Data = (uint8_t*) malloc(DataLen);
   uint64_t fl = fread(Data, 1, DataLen, Ff);
   while(fl){
     if(Verbose>1)
       printf("%lu->", fl);
     try {
       SharcyDecrypt(&Data, fl, Key, KeyLen);
     }
     catch(...){
       fprintf(stderr, "*Error* in Decrypt (may be wrong size of block\n)");
     }
     fwrite(Data, fl, 1, Of);
     if(Verbose>1)
       printf("%lu\n", fl);
     fl = fread(Data, 1, DataLen, Ff);
   }
 }
 else {
   DataLen = FSize;
   Data = (uint8_t*) malloc(DataLen);
   fread(Data, DataLen, 1, Ff);
   try {
     SharcyDecrypt(&Data, DataLen, Key, KeyLen);
   }
   catch(...){
    fprintf(stderr, "*Error* in Decrypt (may be wrong size of block\n)");
   }
   fwrite(Data, DataLen, 1, Of);
 }

 ftime(&tEnd);
 fclose(Ff);
 fclose(Of);
 free(OutFileName);
 free(Data);
}

void usage(void)
{
  printf("\nsharcy 0.1.2, Shark Cypher by Alex Tikhonov (Idea, Alghorythm, Realisation) 2009\n\n");
  printf("Usage: sharcy [switch] [options] file1[ file2[ fileN]]\n");
  printf("switches:\n");
  printf("\t-h\tThis text\n");
  printf("\t-e\tEncrypt file(s) (default for non .scy files)\n");
  printf("\t-d\tDecrypt file(s)\n");
  printf("\t-t\tRandom data test (for research purposes)\n");
  printf("\t\tgenerates SourceFile.dat, DestinationFile.dat, RestoredFile.dat\n");
  printf("options:\n\t-bNNN\tuse NNN as lenght of block\n");
  printf("\t\tdefault block lenghts is nearest power of 2 above lenght of data\n");
  printf("\t-kString, -pString\n\t\tuse String key(password)\n");
  printf("\t-KFile, -PFile\n\t\tuse File as key(password)\n");
  printf("\t-RN\tuse pseudo random (N=0),\n\t\t/dev/urandom (N=1) or\n\t\t/dev/random (N=2) for high quality randomness (Slow as Hell)\n\t\t-R0 is default\n");
  printf("\t-v\tverbose mode\n");
  printf("\t-V\tvery verbose mode\n");
  printf("\n");
}

int main(int argc, char **argv)
{
  if(argc < 2){
    usage();
    return 1;
  }

  Data = NULL;
  Key = NULL;

  timeb t, t2;
  ftime(&t);
  srandom(t.time * (t.millitm+1));

  LittleEndian = IsLittleEndian();
  if(Verbose){
    if(LittleEndian)
      printf("Little Endian");
    else
      printf("Big Endian");
    printf(" Platform detected\n");
  }

  struct sysinfo sinfo;
  sysinfo(&sinfo);
  RAMount = sinfo.totalram * 2 / 3;

  for(int i=1; i<argc; i++)
    if(argv[i][0] != '-')
      continue;
    else
      if(argv[i][1] == 't' || argv[i][1] == 'T')
        RandomTest();
    else
      if(argv[i][1] == 'e' || argv[i][1] == 'E')
        Encrypt = true;
    else
      if(argv[i][1] == 'r' || argv[i][1] == 'R'){
        DevRandom = atoi(&argv[i][2]);
      }
    else
      if(argv[i][1] == 'v')
        Verbose = 1;
    else
      if(argv[i][1] == 'V')
        Verbose = 2;
    else
      if(argv[i][1] == 'd' || argv[i][1] == 'D')
        Encrypt = false;
    else
      if(argv[i][1] == 'h' || argv[i][1] == 'H')
       usage();
    else
      if(argv[i][1] == 'k' || argv[i][1] == 'p'){
        KeyLen = strlen(&argv[i][2]);
        if(!KeyLen) 
          while (!KeyLen){
            char *pas  = getpass("Enter password (will not be echoed): ");
            KeyLen = strlen(pas);
            if(!KeyLen)
              continue;
            Key = (uint8_t*) realloc(Key, KeyLen + 1);
            strcpy((char*)Key, pas);
            pas  = getpass("Reenter password: ");
            if(!strcmp((char*)Key, pas)){
              memset(pas, 0, KeyLen);
            }
            else {
              fprintf(stderr, "*Error* Passwords do not match\n");
              KeyLen = 0;
              continue;
            }
        }
        else {
          Key = (uint8_t*) malloc(KeyLen + 1);
          memcpy(Key, &argv[i][2], KeyLen);
        }
        if(KeyLen%2 == 0)
          KeyLen++;
        Key[KeyLen-1] = 154;
      }
    else
      if(argv[i][1] == 'K' || argv[i][1] == 'P'){
        FILE *kf = fopen(&argv[i][2], "r");
        if(!kf){
          fprintf(stderr, "*Error* Can't open key-file \"%s\"\n", &argv[i][2]);
          return 3;
        }
        fseek(kf, 0, SEEK_END);
        uint64_t FSize = ftell(kf);
        KeyLen = FSize;
        fseek(kf, 0, SEEK_SET);
        Key = (uint8_t*) malloc(KeyLen + 1);
        fread(Key, KeyLen, 1, kf);
        fclose(kf);
        if(KeyLen%2 == 0)
          KeyLen++;
        Key[KeyLen-1] = 154;
      }
    else
      if(argv[i][1] == 'b' || argv[i][1] == 'B'){
        BSize = atoi(&argv[i][2]);
        if(BSize < 1<<7){
          fprintf(stderr, "*Error* Block must be greater than %d\n", 1<<7);
          return 3;
        }
      }

  if(!KeyLen){
    fprintf(stderr, "*Error* No key (password)!\n");
    return 2;
  }

  if(!Random)
  for(int i=1; i<argc; i++)
    if(argv[i][0] != '-'){
    if(strcasestr(&argv[i][0], ".scy") - &argv[i][0] >4  || !Encrypt)
      DecryptFile(&argv[i][0]);
    else
      EncryptFile(&argv[i][0]);
  }

  if(Key)
    free(Key);
  ftime(&t2);
  if(Verbose)
    printf("complete in %ld(%ld) milliseconds\n", (t2.time*1000+t2.millitm)-(t.time*1000+t.millitm), (tEnd.time*1000+tEnd.millitm)-(tBeg.time*1000+tBeg.millitm));
  return 0;
}
