/*
* TCP ���� ä�� ���α׷� ��ȣȭ �� ��ȣȭ �ҽ�����
* �ۼ���: ������Ű��а� 20190895������, ������Ű��а� 20190954 ����ȯ
* �ۼ�ȯ�� : Visual Studio 2022
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>


BYTE Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
BYTE ENC[MAXBYTE]; // ��ȣȭ�Ǿ� ���
BYTE DEC[MAXBYTE]; // ��ȣȭ�Ǿ� ���

/* ��� �� send()�Ǵ� ���� data�� aes_128�� ��ȣȭ�ϴ� �Լ� */
void data_encryption(unsigned char* plain_data, int len) {
	memset(ENC, '\0', MAXBYTE);//��ȣȭ�� �����Ͱ� ��� ���ڿ� �� ��Ҹ� NULL�� �ʱ�ȭ
	while (strlen(plain_data) % 16 != 0)// aes_128�� ��� ������ ������ ��ȣȭ, ��� = 16Byte�̹Ƿ� �ԷµǴ� ������ Input�� 16Byte�� �����ִ� Padding ����
		plain_data[strlen(plain_data)] = ' '; // data���̰� 16���� �ɰ����� ������, ��� ' '�� ��� ���ڿ� ���̸� 16�� ����� ����

	AES_ECB_Encrypt(plain_data, Key, ENC, len);// ��ȣȭ ���� (aes.c�� ����)
}

/* ��� �� recv()�Ǵ� ��ȣȭ�� data�� ��ȣȭ�ϴ� �Լ� */
void data_decryption(unsigned char* cipher_data, int len) {
	memset(DEC, '\0', MAXBYTE);// ��ȣȭ�� �����Ͱ� ��� ���ڿ� �� ��� NULL�� �ʱ�ȭ
	AES_ECB_Decrypt(cipher_data, Key, DEC, len);// ��ȣȭ ���� (aes.c�� ����)
}