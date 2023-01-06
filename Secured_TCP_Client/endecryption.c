/*
* TCP 보안 채팅 프로그램 암호화 및 복호화 소스파일
* 작성자: 정보통신공학과 20190895김찬영, 정보통신공학과 20190954 허진환
* 작성환경 : Visual Studio 2022
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>


BYTE Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
BYTE ENC[MAXBYTE]; // 암호화되어 담길
BYTE DEC[MAXBYTE]; // 복호화되어 담길

/* 통신 중 send()되는 순수 data를 aes_128로 암호화하는 함수 */
void data_encryption(unsigned char* plain_data, int len) {
	memset(ENC, '\0', MAXBYTE);//암호화될 데이터가 담길 문자열 각 요소를 NULL로 초기화
	while (strlen(plain_data) % 16 != 0)// aes_128은 블록 단위로 순차적 암호화, 블록 = 16Byte이므로 입력되는 데이터 Input을 16Byte로 맞춰주는 Padding 과정
		plain_data[strlen(plain_data)] = ' '; // data길이가 16으로 쪼개지지 않으면, 계속 ' '을 찍어 문자열 길이를 16의 배수로 맞춤

	AES_ECB_Encrypt(plain_data, Key, ENC, len);// 암호화 진행 (aes.c에 정의)
}

/* 통신 중 recv()되는 암호화된 data를 복호화하는 함수 */
void data_decryption(unsigned char* cipher_data, int len) {
	memset(DEC, '\0', MAXBYTE);// 복호화될 데이터가 담길 문자열 각 요소 NULL로 초기화
	AES_ECB_Decrypt(cipher_data, Key, DEC, len);// 복호화 진행 (aes.c에 정의)
}