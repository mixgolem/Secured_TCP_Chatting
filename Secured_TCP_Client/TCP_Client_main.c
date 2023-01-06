/*
* TCP ���� ä�� ���α׷� client �ҽ�����
* �ۼ���: ������Ű��а� 20190895������, ������Ű��а� 20190954 ����ȯ
* �ۼ�ȯ�� : Visual Studio 2022
*/

#pragma comment(lib, "ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS


#include <stdio.h>
#include <WinSock2.h>
#include <process.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <time.h>


//��ȣȭ, ��ȣȭ�� �ʿ��� ����
extern BYTE ENC[MAXBYTE];
extern BYTE DEC[MAXBYTE];

//ä�ÿ� �ʿ��� ����
int msgcnt = -1;
int* msgcntp = &msgcnt;
int portnum = 9000;
char ip_addr[256] = "127.0.0.1";
char nickname[16] = "\0";;
BYTE input_msg[MAXBYTE];

//base64 ���ڵ�, ���ڵ��� �ʿ��� �Լ� �� ����
unsigned char* base64_encode(const unsigned char* str, int length, int* ret_length);
unsigned char* base64_decode(const unsigned char* str, int length, int* ret_length);
int encoding_num = 0;
int decoding_num = 1;
static char base64_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};
static char base64_pad = '=';

void gotoxy(int x, int y) {
    COORD pos = { x,y };
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}


//������ ���� IP �� PORTNUM �Է¹޴� �Լ�
int get_server(char ip_addr[]) {
    int portnum2 = 0;
    char in = NULL;

    gotoxy(0, 0);
    printf("������������������������������������������������������������������������������������������������������������������");
    gotoxy(0, 3);
    printf("������������������������������������������������������������������������������������������������������������������");
    gotoxy(0, 1);
    printf("[default server] IP=127.0.0.1 PORTNUM=9000");
    gotoxy(0, 2);
    printf("�����Ϸ��� [m], �״�� �����Ϸ��� [�ٸ� key] �Է�>> ");
    scanf("%c", &in);
    while (getchar() != '\n');//����Ű �Է� ���� ����
    if (in == 'm') {
        system("cls");
        gotoxy(0, 0);
        printf("������������������������������������������������������������������������������������������������������������������");
        gotoxy(0, 3);
        printf("������������������������������������������������������������������������������������������������������������������");
        gotoxy(0, 1);
        printf("������ ������ IP �ּ� �Է�>> ");
        gets(ip_addr);
        gotoxy(0, 2);
        printf("������ ������ PORT NUM �Է�>> ");
        scanf("%d", &portnum2);
        while (getchar() != '\n');//����Ű �Է� ���� ����
        return portnum2;
    }
    else {
        return 9000;
    }

}


//�г��� �Է¹޴� �Լ�
void getnick() {

    gotoxy(0, 0);
    printf("������������������������������������������������������������������������������������������������������������������");
    gotoxy(0, 2);
    printf("������������������������������������������������������������������������������������������������������������������");
    gotoxy(0, 1);
    printf("��ȭ�� �Է�(16byte)>>");
    gets_s(nickname, 16 * sizeof(char));
}

//ä��â ���̾ƿ� ��� �Լ�
void chat_ui() {
    gotoxy(0, 0);
    printf("                                                           ");
    gotoxy(0, 0);
    printf("[TCP client]   [/quit]ä�� ����   [/cls]ȭ�� �ʱ�ȭ\n");
    gotoxy(0, 1);
    printf("����[��ȣȭO]��������������������������������������������������������������������������������������������");
    gotoxy(0, 2);
    printf("                                                            ");
    gotoxy(0, 3);
    printf("                                                            ");
    gotoxy(0, 4);
    printf("��������������������������������������������������������������������������������������������������������������������");
    gotoxy(0, 5);
    printf("                                                            ");
    gotoxy(0, 2);
    printf("[%s] ", nickname);

}

//ä��â ȭ�� Ŭ����
void chatclr() {
    system("cls");
    *msgcntp = -1;
    chat_ui();
}

//wsastartup, socket, connect�Լ� ����
int client_init(char* ip, int port)
{
    SOCKET server_socket;
    WSADATA wsadata;
    SOCKADDR_IN server_address = { 0 };

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)//�����ʱ�ȭ
    {
        printf("WSAStartup ����\n");
        return -1;
    }

    if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)//�������ϻ���
    {
        puts("socket ����.");
        return -1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ip);
    server_address.sin_port = htons(port);

    if ((connect(server_socket, (struct sockaddr*)&server_address, sizeof(server_address))) < 0)//�������Ͽ� ����õ�
    {
        puts("connect ����.");
        return -1;
    }

    return server_socket;
}


//ä���� �����ϴ� �Լ�
unsigned int WINAPI chat(void* params)
{
    SOCKET s = (SOCKET)params;
    BYTE recv_msg[MAXBYTE] = "\0";
    BYTE buf[MAXBYTE] = "\0";
    int len = 0;
    int index = 0;
    int plain_len = 0;//���۹��� �������� ���� Ȯ���ϱ� ���� ����
    int row = 0;//���۹��� �����Ͱ� 60�� �������� �� ������ Ȯ���ϱ� ���ؼ� ����
    WSANETWORKEVENTS ev;
    HANDLE event = WSACreateEvent();


    ////////////FD_READ, FD_CLOSE
    WSAEventSelect(s, event, FD_READ | FD_CLOSE);
    while (1)
    {

        index = WSAWaitForMultipleEvents(1, &event, FALSE, INFINITE, FALSE);
        if ((index != WSA_WAIT_FAILED) && (index != WSA_WAIT_TIMEOUT))
        {
            WSAEnumNetworkEvents(s, event, &ev);
            if (ev.lNetworkEvents == FD_READ)//read�̺�Ʈ ����
            {
                memset(recv_msg, '\0', MAXBYTE);

                int len = recv(s, recv_msg, MAXBYTE, 0);//�޼����� ���Ź޴� ����
                if (len > 0) {
                    if ((*msgcntp) == 40 - 7) {     //Ŭ���̾�Ʈ�� ä��â�� �� á�� ��� ä�� ������ �ʱ�ȭ�ϰ� ������ֱ� ���� ���
                        chatclr();
                    }
                    chat_ui();//�ܼ�â�� ä�� ui�� �ٽ� ����Ѵ�
                    gotoxy(0, (*msgcntp + 7));
                    strcpy(buf, base64_decode(recv_msg, strlen(recv_msg), &decoding_num));  //�޼��� ���Ź޾��� ��� Decoding ����
                    data_decryption(buf, strlen(buf));                                      //Decoding ���� Decryption�ϸ� plain data ȹ��
                    strcpy(recv_msg, DEC);
                    plain_len = strlen(recv_msg);       //UI�� �ϰ����� ���߱� ���� plain data�� ä��â ���� size�� 60�� �̻��� �ѱ� ���
                    row = (int)(plain_len / 60 + 1);    //�̰� ����¥�� ���������� row�� ����
                    (*msgcntp) += row;
                    if (((*msgcntp) + row > 34)) {
                        chatclr();
                    }
                    time_t curr = time(NULL);
                    struct tm* d = localtime(&curr);

                    printf("[%02d:%02d]%s", d->tm_hour, d->tm_min, recv_msg);   //time�Լ��� ����� �����κ��� �޼����� ���۹޾��� ���� �ð� ���
                    row = 0;//row�� 0���� �ٽ� �ʱ�ȭ
                    chat_ui();
                }

            }
            else if (ev.lNetworkEvents == FD_CLOSE)//close�̺�Ʈ �����Ǹ� Ŭ���̾�Ʈ ���� ���� ���� ���� ����
            {
                system("cls");
                printf("[TCP server] �������� ������ ������\n");
                closesocket(s);
                break;
            }

        }
    }
    WSACleanup();
    _endthreadex(0);

    return 0;
}





int main()

{
    system("mode con:cols=60 lines=40");//ä��â ũ�� ����, ����*����



    unsigned int tid;
    int sock;
    BYTE send_msg[MAXBYTE] = "\0";
    BYTE buf[MAXBYTE] = "\0";
    HANDLE mainthread;//�� ������ ����

    portnum = get_server(ip_addr);//���� ������ �Է¹���
    system("cls");
    getnick();  //����� ��ȭ�� �Է¹���
    sock = client_init(ip_addr, portnum);   //���� ����
    if (sock < 0)
    {
        printf("sock_init ����\n");
        exit(0);
    }

    mainthread = (HANDLE)_beginthreadex(NULL, 0, chat, (void*)sock, 0, &tid);
    if (mainthread)
    {
        chatclr();
        while (1)
        {
            memset(input_msg, '\0', MAXBYTE);
            memset(send_msg, '\0', MAXBYTE);
            memset(buf, '\0', MAXBYTE);


            chat_ui();
            gets_s(input_msg, MAXBYTE);

            if (!strcmp(input_msg, "/quit")) {      // quit��ɾ� �Է½� ä�� ����
                break;
            }
            else if (!strcmp(input_msg, "/cls")) {  // cls��ɾ� �Է½� ä�� ������ ǥ�õǴ� ȭ�� �ʱ�ȭ
                chatclr();
                continue;
            }
            else if (((*msgcntp) > 34)) {           // ä��â ȭ���� �� á�� ���, �ڵ����� �ʱ�ȭ
                chatclr();
            }
            else if (strlen(input_msg) == 0) {      // ����ڰ� �Է��� ������ ���� ���, �������� �ʰ� ä�� �ܰ踦 �ݺ�
                continue;
            }

            sprintf(send_msg, "[%s] %s", nickname, input_msg);  //���� �޼����� �г��Ӱ� ���� ������ ���������� ���ؼ� ����


            //������ ���� ��ȣȭ �� ���ڵ�
            data_encryption(send_msg, strlen(send_msg));
            strcpy(send_msg, base64_encode(ENC, strlen(ENC), &encoding_num));




            //�޼��� �����ϴ� �ܰ�
            send(sock, send_msg, MAXBYTE, 0);
            gotoxy(0, (*msgcntp + 7));

        }

        closesocket(sock);
        WSACleanup();
        CloseHandle(mainthread);
    }

    return 0;

}




//base64���ڵ� �� ���ڵ� ���� �Լ�
unsigned char* base64_encode(const unsigned char* str, int length, int* ret_length) {
    const unsigned char* current = str;
    int i = 0;
    unsigned char* result = (unsigned char*)malloc(((length + 3 - length % 3) * 4 / 3 + 1) * sizeof(char));
    while (length > 2) { /* keep going until we have less than 24 bits */
        result[i++] = base64_table[current[0] >> 2];
        result[i++] = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
        result[i++] = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
        result[i++] = base64_table[current[2] & 0x3f];
        current += 3;
        length -= 3; /* we just handle 3 octets of data */
    }
    /* now deal with the tail end of things */
    if (length != 0) {
        result[i++] = base64_table[current[0] >> 2];
        if (length > 1) {
            result[i++] = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
            result[i++] = base64_table[(current[1] & 0x0f) << 2];
            result[i++] = base64_pad;
        }
        else {
            result[i++] = base64_table[(current[0] & 0x03) << 4];
            result[i++] = base64_pad;
            result[i++] = base64_pad;
        }
    }
    if (ret_length) {
        *ret_length = i;
    }
    result[i] = '\0';
    return result;
}

/* as above, but backwards. :) */
unsigned char* base64_decode(const unsigned char* str, int length, int* ret_length) {
    const unsigned char* current = str;
    int ch, i = 0, j = 0, k;
    /* this sucks for threaded environments */
    static short reverse_table[256];
    static int table_built;
    unsigned char* result;
    if (++table_built == 1) {
        char* chp;
        for (ch = 0; ch < 256; ch++) {
            chp = strchr(base64_table, ch);
            if (chp) {
                reverse_table[ch] = chp - base64_table;
            }
            else {
                reverse_table[ch] = -1;
            }
        }
    }
    result = (unsigned char*)malloc(length + 1);
    if (result == NULL) {
        return NULL;
    }
    /* run through the whole string, converting as we go */
    while ((ch = *current++) != '\0') {
        if (ch == base64_pad) break;
        /* When Base64 gets POSTed, all pluses are interpreted as spaces.
        This line changes them back.  It's not exactly the Base64 spec,
        but it is completely compatible with it (the spec says that
        spaces are invalid).  This will also save many people considerable
        headache.  - Turadg Aleahmad <turadg@wise.berkeley.edu>
        */
        if (ch == ' ') ch = '+';
        ch = reverse_table[ch];
        if (ch < 0) continue;
        switch (i % 4) {
        case 0:
            result[j] = ch << 2;
            break;
        case 1:
            result[j++] |= ch >> 4;
            result[j] = (ch & 0x0f) << 4;
            break;
        case 2:
            result[j++] |= ch >> 2;
            result[j] = (ch & 0x03) << 6;
            break;
        case 3:
            result[j++] |= ch;
            break;
        }
        i++;
    }
    k = j;
    /* mop things up if we ended on a boundary */
    if (ch == base64_pad) {
        switch (i % 4) {
        case 0:
        case 1:
            free(result);
            return NULL;
        case 2:
            k++;
        case 3:
            result[k++] = 0;
        }
    }
    if (ret_length) {
        *ret_length = j;
    }
    result[k] = '\0';
    return result;
}