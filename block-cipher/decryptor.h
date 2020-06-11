/*
 * A 32-bit implementation for ARIA
 *
 * follows the specifications given in
 * the ARIA specification at
 * http://www.nsri.re.kr/ARIA/
 *
 * Note:
 *    - Main body optimized for speed for 32 bit platforms
 *       * Utilizes 32-bit optimization techniques presented in ICISC 2003
 *       * Only four 32-bit tables are used
 *
 *    - Implemented some ideas for optimization from the creators of ARIA,
 *         and adopted some ideas from works submitted to ARIA implementation contest on Aug. 2004.
 *
 *    - Handles endian problem pretty well.
 *       * For optimization, for little endian architecture key setup functions return
 *         endian-reversed round keys; Crypt() function handles this correctly.
 *
 * 17, January 2005
 * Aaram Yun
 * National Security Research Institute, KOREA
 *
 * Substantial portion of the code originally written by Jin Hong.
 *
 */


 /*
 * This source code was modified for Cryptanalysis Contest.
 */

#ifdef DECRYPTOR_EXPORTS
#define DECRYPTOR_API __declspec(dllexport)
#else
#define DECRYPTOR_API __declspec(dllimport)
#endif // DECRYPTOR_EXPORTS


#define LITTLE_ENDIAN

 /*********************************************************/

#include <stdio.h>
#include <stdlib.h>

#ifdef BIG_ENDIAN
#undef LITTLE_ENDIAN
#else
#ifndef LITTLE_ENDIAN
#error In order to compile this, you have to	\
  define either LITTLE_ENDIAN or BIG_ENDIAN.	\
  If unsure, try define either of one and run	\
  checkEndian() function to see if your guess	\
  is correct.
#endif
#endif

typedef unsigned char Byte;
typedef unsigned int  Word;

/* S-box들을 정의하기 위한 마크로. */

#define AAA(V) 0x ## 00 ## V ## V ## V
#define BBB(V) 0x ## V ## 00 ## V ## V
#define CCC(V) 0x ## V ## V ## 00 ## V
#define DDD(V) 0x ## V ## V ## V ## 00
#define XX(NNN,x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf)		\
  NNN(x0),NNN(x1),NNN(x2),NNN(x3),NNN(x4),NNN(x5),NNN(x6),NNN(x7),	\
    NNN(x8),NNN(x9),NNN(xa),NNN(xb),NNN(xc),NNN(xd),NNN(xe),NNN(xf)

/* BY(X, Y)는 Word X의 Y번째 바이트
 * BRF(T,R)은 T>>R의 하위 1바이트
 * WO(X, Y)는 Byte array X를 Word array로 간주할 때 Y번째 Word
 */

#define BY(X,Y) (((Byte *)(&X))[Y])
#define BRF(T,R) ((Byte)((T)>>(R)))
#define WO(X,Y) (((Word *)(X))[Y])

 /* abcd의 4 Byte로 된 Word를 dcba로 변환하는 함수  */
#if defined(_MSC_VER)
/* MSC 사용 환경의 경우에는 _lrotr() 함수를
 * 이용할 수 있으므로 약간의 속도 향상이 가능하다. */
#define ReverseWord(W) {						\
    (W)=(0xff00ff00 & _lrotr((W), 8)) ^ (0x00ff00ff & _lrotl((W), 8));	\
  }
#else
#define ReverseWord(W) {						\
    (W)=(W)<<24 ^ (W)>>24 ^ ((W)&0x0000ff00)<<8 ^ ((W)&0x00ff0000)>>8;	\
  }
#endif

/* Byte array를 Word에 싣는 함수.  LITTLE_ENDIAN의 경우
 * 엔디안 변환 과정을 거친다. */
#ifdef LITTLE_ENDIAN
#define WordLoad(ORIG, DEST) {			\
    Word ___t;					\
    BY(___t,0)=BY(ORIG,3);			\
    BY(___t,1)=BY(ORIG,2);			\
    BY(___t,2)=BY(ORIG,1);			\
    BY(___t,3)=BY(ORIG,0);			\
    DEST=___t;					\
  }
#else
#define WordLoad(ORIG, DEST) {			\
    DEST = ORIG;				\
  }
#endif

#if defined(_MSC_VER)
#undef WordLoad
#define WordLoad(ORIG, DEST) {						\
    (DEST) = (0xff00ff00 & _lrotr((ORIG), 8)) ^ (0x00ff00ff & _lrotl((ORIG), 8)); \
  }
#endif

 /* Key XOR Layer */
#define KXL {							\
    t0^=WO(rk,0); t1^=WO(rk,1); t2^=WO(rk,2); t3^=WO(rk,3);	\
    rk += 16;							\
  }

/* S-Box Layer 1 + M 변환 */
#define SBL1_M(T0,T1,T2,T3) {						\
    T0=S1[BRF(T0,24)]^S2[BRF(T0,16)]^X1[BRF(T0,8)]^X2[BRF(T0,0)];	\
    T1=S1[BRF(T1,24)]^S2[BRF(T1,16)]^X1[BRF(T1,8)]^X2[BRF(T1,0)];	\
    T2=S1[BRF(T2,24)]^S2[BRF(T2,16)]^X1[BRF(T2,8)]^X2[BRF(T2,0)];	\
    T3=S1[BRF(T3,24)]^S2[BRF(T3,16)]^X1[BRF(T3,8)]^X2[BRF(T3,0)];	\
  }
/* S-Box Layer 2 + M 변환 */
#define SBL2_M(T0,T1,T2,T3) {						\
    T0=X1[BRF(T0,24)]^X2[BRF(T0,16)]^S1[BRF(T0,8)]^S2[BRF(T0,0)];	\
    T1=X1[BRF(T1,24)]^X2[BRF(T1,16)]^S1[BRF(T1,8)]^S2[BRF(T1,0)];	\
    T2=X1[BRF(T2,24)]^X2[BRF(T2,16)]^S1[BRF(T2,8)]^S2[BRF(T2,0)];	\
    T3=X1[BRF(T3,24)]^X2[BRF(T3,16)]^S1[BRF(T3,8)]^S2[BRF(T3,0)];	\
  }
/* 워드 단위의 변환 */
#define MM(T0,T1,T2,T3) {			\
    (T1)^=(T2); (T2)^=(T3); (T0)^=(T1);		\
    (T3)^=(T1); (T2)^=(T0); (T1)^=(T2);		\
  }
/* P 변환.  확산 계층의 중간에 들어가는 바이트 단위 변환이다.
 * 이 부분은 endian과 무관하다.  */
#if defined(_MSC_VER)
#define P(T0,T1,T2,T3) {					\
    (T1) = (((T1)<< 8)&0xff00ff00) ^ (((T1)>> 8)&0x00ff00ff);	\
    (T2) = _lrotr((T2),16);					\
    ReverseWord((T3));						\
  }
#else
#define P(T0,T1,T2,T3) {					\
    (T1) = (((T1)<< 8)&0xff00ff00) ^ (((T1)>> 8)&0x00ff00ff);	\
    (T2) = (((T2)<<16)&0xffff0000) ^ (((T2)>>16)&0x0000ffff);	\
    ReverseWord((T3));						\
  }
#endif

 /* FO: 홀수번째 라운드의 F 함수
  * FE: 짝수번째 라운드의 F 함수
  * MM과 P는 바이트 단위에서 endian에 무관하게 동일한 결과를 주며,
  * 또한 endian 변환과 가환이다.  또한, SBLi_M은 LITTLE_ENDIAN에서
  * 결과적으로 Word 단위로 endian을 뒤집은 결과를 준다.
  * 즉, FO, FE는 BIG_ENDIAN 환경에서는 ARIA spec과 동일한 결과를,
  * LITTLE_ENDIAN 환경에서는 ARIA spec에서 정의한 변환+endian 변환을
  * 준다. */
#define FO {SBL1_M(t0,t1,t2,t3) MM(t0,t1,t2,t3) P(t0,t1,t2,t3) MM(t0,t1,t2,t3)}
#define FE {SBL2_M(t0,t1,t2,t3) MM(t0,t1,t2,t3) P(t2,t3,t0,t1) MM(t0,t1,t2,t3)}

  /* n-bit right shift of Y XORed to X */
  /* Word 단위로 정의된 블록에서의 회전 + XOR이다. */
#define GSRK(X, Y, n) {							\
    q = 4-((n)/32);							\
    r = (n) % 32;							\
    WO(rk,0) = ((X)[0]) ^ (((Y)[(q  )%4])>>r) ^ (((Y)[(q+3)%4])<<(32-r)); \
    WO(rk,1) = ((X)[1]) ^ (((Y)[(q+1)%4])>>r) ^ (((Y)[(q  )%4])<<(32-r)); \
    WO(rk,2) = ((X)[2]) ^ (((Y)[(q+2)%4])>>r) ^ (((Y)[(q+1)%4])<<(32-r)); \
    WO(rk,3) = ((X)[3]) ^ (((Y)[(q+3)%4])>>r) ^ (((Y)[(q+2)%4])<<(32-r)); \
    rk += 16;								\
  }

/* DecKeySetup()에서 사용하는 마크로 */
#if defined(_MSC_VER)
#define WordM1(X,Y) {				\
    w=_lrotr((X), 8);				\
    (Y)=w^_lrotr((X)^w, 16);			\
  }
#else
#define WordM1(X,Y) {						\
    Y=(X)<<8 ^ (X)>>8 ^ (X)<<16 ^ (X)>>16 ^ (X)<<24 ^ (X)>>24;	\
  }
#endif

struct CTX
{
	Byte* ciphertext;
	int cipher_length;
	Byte* IV;
};

/* 암호화 함수.
 * const Byte *i: 입력
 * int Nr: 라운드 수
 * const Byte *rk: 라운드 키들
 * Byte *o: 출력
 */
extern "C" DECRYPTOR_API void Crypt(const Byte* i, int Nr, const Byte* rk, Byte* o);

/* 암호화 라운드 키 생성
 * const Byte *mk: 마스터 키
 * Byte *rk: 라운드 키
 * int keyBits: 마스터 키의 길이
 */
extern "C" DECRYPTOR_API int EncKeySetup(const Byte* mk, Byte* rk, int keyBits);

/* 복호화 라운드 키 생성
 * const Byte *mk: 마스터 키
 * Byte *rk: 라운드 키
 * int keyBits: 마스터 키의 길이
 */
extern "C" DECRYPTOR_API int DecKeySetup(const Byte* mk, Byte* rk, int keyBits);

/* 복호화 및 패딩 확인 모듈
 * struct CTX* ctx: 암호문 context
 */
extern "C" DECRYPTOR_API int Dec_CTX(struct CTX* ctx);