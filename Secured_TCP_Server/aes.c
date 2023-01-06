/*
* AES��ȣȭ�� ���� �ҽ�����
* �ڵ� : https://blog.naver.com/PostView.naver?blogId=dldvk9999&logNo=222033773276&parentCategoryNo=&categoryNo=5&viewDate=&isShowPopularPosts=false&from=postView
* �ּ� : 20190954 ����ȯ
* �ۼ�ȯ�� : Visual Studio 2022
*/

#include <string.h>
#include "aes.h"

#ifdef AES256
#define KEYLEN      32
#elif defined(AES192)
#define KEYLEN      24
#else
#define KEYLEN      16
#endif

#define Nr          (KEYLEN/8+3)*2 // ���� ���� ����. ������, ����ȯ �� �ڵ忡���� Ű ����(KEYLEN)�� 16Bytes = 128bits�̹Ƿ� AES-128 
// AES-128 -> �ʱ�  ���� Round0�� ������ �� Round �� = 10�̹Ƿ� Nr==10
#define KEYEXPSIZE  (Nr+1)*16 // �ʱ� ����(Round0)�� ������ �� ���帶�� �ʿ��� Ű�� �� �� Nr+1�� ��(Ű) ������ 16�� ���� �־�ȣŰ+����Ű�޸� �뷮 ����
#define BLOCKLEN    16

#define SWAP(T,A,B)         {T=A; A=B; B=T;} // shiftrows�ܰ迡�� ����Ǵ� swap ����
#define ROTATE(T,A,B,C,D)   {T=A; A=B; B=C; C=D; D=T;} // shiftrows�ܰ迡�� ����Ǵ� rotate ����

// SubBytes�ܰ迡�� 4(bytes)x4(bytes)=16(bytes)�� ����� �ٸ� �������� ġȯ�� �� ������ �Ǵ� s-box ����
LOCAL(VOID) GetSBox(LPBYTE TA) {
	static CONST BYTE SBox[256] = {
		//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	TA[0] = SBox[TA[0]];
	TA[1] = SBox[TA[1]];
	TA[2] = SBox[TA[2]];
	TA[3] = SBox[TA[3]];
}

// KeyExpansion() : �־��� �ϳ��� �־�ȣŰ(deencryption.c �� �����)�� ���� ���� Ű�� ����� ��.
// 1. ���� Ű ���� �� �� �� �� �����ǰ�, �����Ǵ� �ش� ��(i��°) �������� �� ���� ��(i-1��°)�� ���� RotWord(�ش� �� ù ��° ��� ������(4��°) �� ���� �ٲ�) ����
// 2. �� ������ �����(i-1��°�� RotWord �����) ���� ���� S-BOX�� �������� ������ ġȯ�� �����Ѵ�. 
// 3. ���� �ش� ���� i-4��° ��, Rcon�� ���� (3input)XOR������ �����ϸ� i��° ���� ���������.
// 4. �� ������ �ݺ��Ǿ� �־�ȣŰ�� ������ 10���� ���� Ű�� �����ȴ�. (128bit AES�̹Ƿ� �� 11���� ����ǹǷ� �ʱ���� Round0 ���� �� 10��)
LOCAL(VOID) KeyExpansion(LPBYTE ExpKey, LPCBYTE Key) {
	BYTE TA[4];
	static CONST BYTE Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }; // Rcon(Row Constant) ��� �迭 ����

	memcpy(ExpKey, Key, KEYLEN);

	for (int i = KEYLEN; i < KEYEXPSIZE; i += 4) {
		memcpy(TA, ExpKey + i - 4, 4);

		if (i % KEYLEN == 0) {
			int T = TA[0];
			TA[0] = TA[1];
			TA[1] = TA[2];
			TA[2] = TA[3];
			TA[3] = T;

			GetSBox(TA);
			TA[0] ^= Rcon[i / KEYLEN];
		}
#if defined(AES256)
		if (i % KEYLEN == 16) GetSBox(TA);
#endif
		ExpKey[i + 0] = ExpKey[i - KEYLEN + 0] ^ TA[0];
		ExpKey[i + 1] = ExpKey[i - KEYLEN + 1] ^ TA[1];
		ExpKey[i + 2] = ExpKey[i - KEYLEN + 2] ^ TA[2];
		ExpKey[i + 3] = ExpKey[i - KEYLEN + 3] ^ TA[3];
	}
}


// KeyExpansion()���� ����Ǿ� ������� RoundKey�� ���� �ϳ��� ��ġ�Ǵ� �� block�� ���� ���� xor������ �� ���� ������ ��(4��° ��(State[3][n])�� ù��° ���� ������.
// �� �� ������ ���鿡 ���ؼ��� ���� �����Ǵ� RoundKey�� xor�����Ͽ� ���� ���� ��ü�Ѵ�.
LOCAL(VOID) AddRoundKey(BYTE State[4][4], LPBYTE ExpKey, BYTE Round) {
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			State[i][j] ^= ExpKey[Round * 4 * 4 + i * 4 + j];
}

//Data�� SBox�� �ִ� �������� ġȯ�Ѵ�. ex) 19 -> d4 // ��(x)=1, ��(y)=9 �� ��Ī�Ǵ� sbox�� d4
LOCAL(VOID) SubBytes(BYTE State[4][4]) {
	for (int i = 0; i < 4; i++) GetSBox(State[i]);
}

// �� data��Ͽ� ���� 2��° ������ 1���� rotate, 3��° ������ 2���� rotate, 4��° ������ 3���� rotate ����
LOCAL(VOID) ShiftRows(BYTE State[4][4]) {
	BYTE T;

	ROTATE(T, State[0][1], State[1][1], State[2][1], State[3][1]); // 2��° ��(state[n][1])�� ���� rotate 1�� ����

	SWAP(T, State[0][2], State[2][2]); // 3��° ��(state[n][2])�� ���� rotate 1�� ���� ��ü�� ��ġ�Ǵ� ��ȣ�� swap ����
	SWAP(T, State[1][2], State[3][2]);

	ROTATE(T, State[0][3], State[3][3], State[2][3], State[1][3]); //  4��° ��(state[n][3])�� ���� rotate 3�� ���� -> ���� �ݴ�� 1�� �������� ��ü
}

// ��ȣȭ �� ShiftRows()�� ���� -> ShiftRows()�� �������� ����
LOCAL(VOID) InvShiftRows(BYTE State[4][4]) {
	BYTE T;

	ROTATE(T, State[3][1], State[2][1], State[1][1], State[0][1]);

	SWAP(T, State[0][2], State[2][2]);
	SWAP(T, State[1][2], State[3][2]);

	ROTATE(T, State[0][3], State[1][3], State[2][3], State[3][3]);
}

LOCAL(int) XTime(int X) {
	return ((X << 1) & 0xFF) ^ (((X >> 7) & 1) * 0x1B);
}

// ������ ���� ��� 4x4��İ� ���Ͽ� �ش� ���� �����͸� ���ο� ������ ��ü������
/* �־����� ������ : 2 3 1 1
					   1 2 3 1
					   1 1 2 3
					   3 1 1 2 */
LOCAL(VOID) MixColumns(BYTE State[4][4]) {
	for (int i = 0; i < 4; i++) {
		int T1 = State[i][0];
		int T2 = State[i][0] ^ State[i][1] ^ State[i][2] ^ State[i][3];
		State[i][0] ^= XTime(State[i][0] ^ State[i][1]) ^ T2;
		State[i][1] ^= XTime(State[i][1] ^ State[i][2]) ^ T2;
		State[i][2] ^= XTime(State[i][2] ^ State[i][3]) ^ T2;
		State[i][3] ^= XTime(State[i][3] ^ T1) ^ T2;
	}
}

LOCAL(int) Multiply(int X, int Y) {
	return  ((Y >> 0 & 1) * X) ^
		((Y >> 1 & 1) * XTime(X)) ^
		((Y >> 2 & 1) * XTime(XTime(X))) ^
		((Y >> 3 & 1) * XTime(XTime(XTime(X)))) ^
		((Y >> 4 & 1) * XTime(XTime(XTime(XTime(X)))));
}

// ��ȣȭ �� MixColumns()�� ���� -> MixColumns()�� �������� ����
LOCAL(VOID) InvMixColumns(BYTE State[4][4]) {
	for (int i = 0; i < 4; i++) {
		int A = State[i][0];
		int B = State[i][1];
		int C = State[i][2];
		int D = State[i][3];

		State[i][0] = Multiply(A, 0x0E) ^ Multiply(B, 0x0B) ^ Multiply(C, 0x0D) ^ Multiply(D, 0x09);
		State[i][1] = Multiply(A, 0x09) ^ Multiply(B, 0x0E) ^ Multiply(C, 0x0B) ^ Multiply(D, 0x0D);
		State[i][2] = Multiply(A, 0x0D) ^ Multiply(B, 0x09) ^ Multiply(C, 0x0E) ^ Multiply(D, 0x0B);
		State[i][3] = Multiply(A, 0x0B) ^ Multiply(B, 0x0D) ^ Multiply(C, 0x09) ^ Multiply(D, 0x0E);
	}
}

// SubBytes�ܰ迡�� s-box �������� ġȯ�� 4(bytes)x4(bytes)=16(bytes)�� ��� �ٽ� �������� ġȯ�� �� ������ �Ǵ� SBoxInvert ����
static VOID InvSubBytes(BYTE State[4][4]) {
	static CONST BYTE SBoxInvert[256] = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	};

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++) State[j][i] = SBoxInvert[State[j][i]];
}

// ���� ��ȣȭ ���� -> ������, ����ȯ �� ���� AES_128(bits)�� �� Round�� 11�� �����(�ʱ� Round 0 ����).
LOCAL(VOID) Cipher(BYTE State[4][4], LPBYTE ExpKey) {
	AddRoundKey(State, ExpKey, 0); // Round0������ AddRoundKey() ����

	for (int Round = 1; Round < Nr; Round++) { // AES_128�̹Ƿ� Nr(�ʱ� ����(Round0) ���� ���� ��) == 10�̰�, Round0�� ������ Round1~9������ �� 1~4���� 9�� �ݺ�
		SubBytes(State); // 1. SubBytes()
		ShiftRows(State); // 2. ShiftRows()
		MixColumns(State); // 3. MixColumns()
		AddRoundKey(State, ExpKey, Round); // 4. AddRoundKey()
	} // ������� ������ �� �ʱ� Round ���� �� Round �� = 10

	// ������ Round10����
	SubBytes(State);
	ShiftRows(State);
	// Round10���� MixCollum()���� ����
	AddRoundKey(State, ExpKey, Nr); // ��� ���� ��ġ�� �ʱ� Round ���� �� Round �� = 11 -> AES_128���� �� Round �� = 11
}

// ���� ��ȣȭ ����
LOCAL(VOID) InvCipher(BYTE State[4][4], LPBYTE ExpKey) {
	AddRoundKey(State, ExpKey, Nr);

	for (int Round = Nr - 1; Round > 0; Round--) {
		InvShiftRows(State);
		InvSubBytes(State);
		AddRoundKey(State, ExpKey, Round);
		InvMixColumns(State);
	}

	InvShiftRows(State);
	InvSubBytes(State);
	AddRoundKey(State, ExpKey, 0);
}

// CBC
#if CBC
LOCAL(VOID) XorWithIv(LPBYTE Buff, LPCBYTE Iv) {
	for (int i = 0; i < BLOCKLEN; i++) Buff[i] ^= Iv[i];
}

extern VOID WINAPI AES_CBC_Encrypt(LPBYTE Output, LPBYTE Input, int Length, LPCBYTE Key, LPCBYTE Iv) {
	BYTE ExpKey[KEYEXPSIZE];

	int Extra = Length % BLOCKLEN;
	KeyExpansion(ExpKey, Key);

	for (int i = 0; i < Length; i += BLOCKLEN) {
		XorWithIv(Input, Iv);
		memcpy(Output, Input, BLOCKLEN);
		Cipher((BYTE(*)[4])Output, ExpKey);
		Iv = Output;
		Input += BLOCKLEN;
		Output += BLOCKLEN;
	}

	if (Extra) {
		memcpy(Output, Input, Extra);
		Cipher((BYTE(*)[4])Output, ExpKey);
	}
}

extern VOID WINAPI AES_CBC_Decrypt(LPBYTE Output, LPCBYTE Input, int Length, LPCBYTE Key, LPCBYTE Iv) {
	BYTE ExpKey[KEYEXPSIZE];

	int Extra = Length % BLOCKLEN;
	KeyExpansion(ExpKey, Key);

	for (int i = 0; i < Length; i += BLOCKLEN) {
		memcpy(Output, Input, BLOCKLEN);
		InvCipher((BYTE(*)[4])Output, ExpKey);
		XorWithIv(Output, Iv);
		Iv = Input;
		Input += BLOCKLEN;
		Output += BLOCKLEN;
	}

	if (Extra) {
		memcpy(Output, Input, Extra);
		InvCipher((BYTE(*)[4])Output, ExpKey);
	}
}
#endif

// ECB -> ������, ����ȯ �� ��� AES���(��� ������ ������ ��ȣȭ, ���=16Byte�̹Ƿ� �ԷµǴ� ������ Input�� 16Byte�� �����ִ� Padding ������ �ʿ�)
#if ECB
// AES_ECB ��ȣȭ �Լ�
VOID WINAPI AES_ECB_Encrypt(LPCBYTE Input, LPCBYTE Key, LPBYTE Output, int Length) {
	BYTE ExpKey[KEYEXPSIZE]; // �� Key ������(�־�ȣŰ+�� ����Ű)�� �޾� Ű���� ����� ����(����) ����

	memcpy(Output, Input, Length);
	KeyExpansion(ExpKey, Key); // �ʱ� Key Expansion�� ���� �� ���� ����Ű ����
	Cipher((BYTE(*)[4])Output, ExpKey); // �־�ȣŰ�� ����Ű�� ���� ��ȣȭ
}
// AES_ECB ��ȣȭ �Լ��� ���� ��ȣȭ�� ����
VOID WINAPI AES_ECB_Decrypt(LPCBYTE Input, LPCBYTE Key, LPBYTE Output, int Length) {
	BYTE ExpKey[KEYEXPSIZE];

	memcpy(Output, Input, Length);
	KeyExpansion(ExpKey, Key);
	InvCipher((BYTE(*)[4])Output, ExpKey);
}
#endif