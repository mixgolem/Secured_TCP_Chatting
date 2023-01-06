/*
* TCP ���� ä�� ���α׷� server �ҽ�����
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
#include <time.h>
#define MAXCLIENT 10    //�ִ� Ŭ���̾�Ʈ �� ����
#define PORTNUM 9000    //���� Port��ȣ


//�ֿܼ� ��µǴ� �޼����� �����ڵ带 �ο���
void textcolor(int colorNum) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colorNum);
}


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



//��ȣȭ, ��ȣȭ�� �ʿ��� ����
extern int length;          //��ȣȭ�� ���ڿ��� ����
extern BYTE ENC[MAXBYTE];   //��ȣȭ �Լ� ���� ENC�� ��ȣȭ�� ���� ����
extern BYTE DEC[MAXBYTE];   //��ȣȭ �Լ� ���� DEC�� ��ȣȭ�� ���� ����


//TCP���� ���ۿ� ���õ� ����� ���� �Լ�
void server_setup();
int server_init();
int server_close();
unsigned int WINAPI chat(void* param);
unsigned int WINAPI recv_and_forward(void* param);
int add_client(int index);
int read_client(int index);
void remove_client(int index);
int notify_client(char* message);
char* get_client_ip(int index);
//���Ͽ� HANDLE event�� �����Ͽ� ����ü ����
typedef struct sock_info {
    SOCKET s;
    HANDLE ev;
} SOCK_INFO;

SOCK_INFO sock_array[MAXCLIENT + 1];    //���� �迭�� ����
int total_socket_count = 0;             //�ʱ� ���� �迭�� �� = 0



//�ΰ��� IP�� ������ �����ϰ� �ϱ� ���� ���� ���� �� SETUP�ϴ� �Լ�
//���� ���� ��� IP�ּҴ� stack�� ����Ǿ� �����ȴ� (stack�Լ��� stack.c�� ����)
//����� ���� �Լ� search_num()�� search_stack() �Լ��� �����Ͽ� ���������� pop �̿��� ���ϴ� �������� ���� ������ �߰��Ͽ���
void server_setup() {
    printf("[TCP server] ���α׷��� �����Ϸ��� [ENTER]\n");
    int count = 0;
    while (1)       //����ڷκ��� ��� �Է¹���
    {
        char command = NULL;
        char buffer[32];


        while (getchar() != '\n');//�Է� ���� ����
        printf("[IP�ּ� �߰�/����] ([a] : add / [d] : delete / [s] : show IP add / [l] : listen) : ");
        scanf("%c", &command);
        if (command == 'a')
        {
            printf(">>�߰��� IP�ּ� �Է� : ");
            scanf("%s", buffer);
            if (search_stack(buffer) == NULL)
                push(buffer);
            else
                printf("�ߺ��� IP�ּ��Դϴ�.\n");
        }
        else if (command == 'd')
        {
            printf(">>������ IP�ּ� �Է�: ");
            scanf("%s", buffer);
            count = search_num(buffer);
            if (search_stack(buffer) != NULL)
            {
                search_pop(count);
                printf("%s�� �����Ǿ����ϴ�\n", buffer);
            }
            else
                printf("������� ���� IP�Դϴ�\n");
        }
        else if (command == 's')
        {
            printf("\n[�ΰ���(���ÿ� �����) IP�ּ�]\n");
            printf("������������������������������������������������������������������������������������������������������������������������������������\n");
            print_stack();
            printf("������������������������������������������������������������������������������������������������������������������������������������\n");
            printf("\n");
        }
        else if (command == 'l')
        {
            while (getchar() != '\n');
            break;
        }
        else
        {
            printf("�߸� �Է��ϼ̽��ϴ�\n\n");
        }

    }
}

//���� ���� �� ������ �ʱ�ȭ�ϴ� �ܰ�
//winsock �ʱ�ȭ, server socket ����, bind, listen �ܰ踦 �����Ѵ�
int server_init()
{
    WSADATA wsadata;
    SOCKET s;
    SOCKADDR_IN server_address;

    memset(&sock_array, 0, sizeof(sock_array));
    total_socket_count = 0;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)//WINSOCK �ʱ�ȭ
    {
        puts("WSAStartup ����.");//���� �߻� �� �����޼��� ���
        return -1;
    }

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)//SERVER SOCKET ����
    {
        puts("socket ����.");//���� �߻� �� �����޼��� ���
        return -1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORTNUM);//������ PORTNUMBER�� �ҽ����� �ֻ�ܿ� ����

    //bind �ܰ�
    if (bind(s, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
    {
        puts("bind ����");
        return -2;
    }


    //listen �ܰ�
    if (listen(s, SOMAXCONN) < 0)
    {
        puts("listen ����");
        return -3;
    }

    return s;
}

//���� ���� �� sock_array�� ����� ��� socket�� �����ϰ� �̺�Ʈ ��ü �ڵ��� ����
int server_close()
{
    for (int i = 1; i < total_socket_count; i++)
    {
        closesocket(sock_array[i].s);
        WSACloseEvent(sock_array[i].ev);
    }

    return 0;
}

//2���� ������ ���� �� ���������� ��� ����
//���� ���� �ʱ�ȭ �� ���������� ����� Ŭ���̾�Ʈ�κ��� ������ �̺�Ʈ�� �ִ��� �̺�Ʈ�� ����͸�(���� ������ ��ٸ�)
//�̺�Ʈ���� FD_ACCEPT(Ŭ���̾�Ʈ ����), FD_READ(�޼��� ����), FD_CLOSE(Ŭ���̾�Ʈ ���� ����)
//�������� ��� �� ä���� ���� ����� ���� �Լ�
unsigned int WINAPI chat(void* param)
{
    SOCKET  server_socket;
    WSANETWORKEVENTS ev;
    int index;
    WSAEVENT handle_array[MAXCLIENT + 1];

    server_socket = server_init();
    if (server_socket < 0)
    {
        printf("�ʱ�ȭ ����\n");
        exit(0);
    }
    else
    {
        printf("\n[TCP server] ���� �ʱ�ȭ �Ϸ� (��Ʈ��ȣ:%d) Ŭ���̾�Ʈ ������ ���\n", PORTNUM);

        HANDLE event = WSACreateEvent();//��Ʈ��ũ �̺�Ʈ ��ü ����
        sock_array[total_socket_count].ev = event;
        sock_array[total_socket_count].s = server_socket;

        WSAEventSelect(server_socket, event, FD_ACCEPT);
        total_socket_count++;

        while (1)
        {
            memset(&handle_array, 0, sizeof(handle_array));
            for (int i = 0; i < total_socket_count; i++)
                handle_array[i] = sock_array[i].ev;

            index = WSAWaitForMultipleEvents(total_socket_count,//�̺�Ʈ ��ü�� ��ȣ ���°� �Ǳ⸦ ��ٸ���
                handle_array, FALSE, INFINITE, FALSE);
            if ((index != WSA_WAIT_FAILED) && (index != WSA_WAIT_TIMEOUT))
            {
                WSAEnumNetworkEvents(sock_array[index].s, sock_array[index].ev, &ev);//�߻��� ��Ʈ��ũ �̺�Ʈ�� �˾Ƴ���, ������ ���� �Լ� ȣ�� �� ó��
                if (ev.lNetworkEvents == FD_ACCEPT)//Ŭ���̾�Ʈ ���� �̺�Ʈ ������ add_client
                    add_client(index);
                else if (ev.lNetworkEvents == FD_READ)//Ŭ���̾�Ʈ�� �޼��� ������ ��� read_client
                    read_client(index);
                else if (ev.lNetworkEvents == FD_CLOSE)//Ŭ���̾�Ʈ ���� ����� remove_client
                    remove_client(index);
            }
        }
        closesocket(server_socket);
    }

    WSACleanup();
    _endthreadex(0);

    return 0;

}

//WSAeventselect��(���� 10.4�� 402pg)
//ACCEPT�� ���� �� �̺�Ʈ�� ����� ������ SOCK_INFO �迭�� ����
//Ŭ���̾�Ʈ ���� �̺�Ʈ �߻����� ��� ����Ǵ� �Լ�
int add_client(int index)
{
    SOCKADDR_IN addr;
    int len = 0;
    SOCKET accept_sock;
    char msg[256] = "\0";
    memset(msg, '\0', MAXBYTE);
    if (total_socket_count == FD_SETSIZE)
        return 1;
    else {

        len = sizeof(addr);
        memset(&addr, 0, sizeof(addr));
        accept_sock = accept(sock_array[0].s, (SOCKADDR*)&addr, &len);

        if (search_stack(inet_ntoa(addr.sin_addr)) == NULL) {
            textcolor(4);
            printf("\n[TCP server] �ΰ����� ���� IP ���� �õ� (IP�ּ�: %s, port: %d)\n",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            textcolor(7);
            sprintf(msg, "\n[TCP server] �ΰ����� ���� IP ���� �õ� (IP�ּ�: %s, port: %d)\n",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            notify_client(msg);
            closesocket(accept_sock);   //�켱 ��� Ŭ���̾�Ʈ�� ���ؼ� accept�� ����, IP�ּҸ� �о�� stack���� IP�� ���Ͽ� ���� ��� ���� ������ ������ ������
            return 1;
        }
        else {
            HANDLE event = WSACreateEvent();//�ΰ��� IP�� �������� ��� �̺�Ʈ ����
            sock_array[total_socket_count].ev = event;
            sock_array[total_socket_count].s = accept_sock;

            WSAEventSelect(accept_sock, event, FD_READ | FD_CLOSE);//���� �̺�Ʈ�� ������ϱ� ���� FD_READ�� FD_CLOSE �̺�Ʈ�� ���

            total_socket_count++;
            printf("[TCP server] ���ο� ����� ���� (IP�ּ�: %s)\n", inet_ntoa(addr.sin_addr));


            sprintf(msg, "[TCP server] ���ο� ����� ����\n");
            notify_client(msg);
        }

    }

    return 0;
}


//�����带 �߰������� �����ؼ� Ŭ���̾�Ʈ�� �۽��� �޼����� �����ϰ� ������ �޼����� �� Ŭ���̾�Ʈ�鿡�� �����Ѵ�
int read_client(int index)
{
    unsigned int tid;
    HANDLE mainthread = (HANDLE)_beginthreadex(NULL, 0, recv_and_forward, (void*)index, 0, &tid);
    WaitForSingleObject(mainthread, INFINITE);

    CloseHandle(mainthread);

    return 0;
}

//send�� encryption �� encoding, recv�� decoding �� decryption
unsigned int WINAPI recv_and_forward(void* param)
{
    int index = (int)param;
    BYTE recv_msg[MAXBYTE] = "\0";
    BYTE send_msg[MAXBYTE] = "\0";
    BYTE buf[MAXBYTE] = "\0";
    SOCKADDR_IN client_address;
    int recv_len = 0, addr_len = 0;

    memset(&client_address, 0, sizeof(client_address));
    memset(recv_msg, '\0', MAXBYTE);
    memset(send_msg, '\0', MAXBYTE);
    memset(buf, '\0', MAXBYTE);



    //CLIENT �޼��� �Է�->CLIENT ��ȣȭ->CLIENT ���ڵ�->CLIENT���� ����->
    //SERVER ����->SERVER ���ڵ�->SERVER ��ȣȭ
    //SERVER ��ȣȭ->SERVER ���ڵ�->SERVER���� ����->��� CLIENT����
    //Ŭ���̾�Ʈ�κ��� ���� �����ʹ� ��ȣȭ�� �� ���ڵ��Ǿ���
    recv_len = recv(sock_array[index].s, recv_msg, MAXBYTE, 0);
    if (recv_len > 0)
    {
        addr_len = sizeof(client_address);
        getpeername(sock_array[index].s, (SOCKADDR*)&client_address, &addr_len);

        //Ŭ���̾�Ʈ�κ��� ���� �޼����� ���ڵ�(base64_decode) �ؼ� buf�� ����
        strcpy(buf, base64_decode(recv_msg, strlen(recv_msg), &decoding_num));

        printf("������������������������������������������������������������������������������������������������������������������������������������\n");
        printf(" * Client recv()�� ���� Encoded+Encrypted data�Դϴ�\n");
        textcolor(6);
        printf("%s\n", recv_msg);
        textcolor(7);
        printf(" * ���� Decoding�ϸ�, Encrypted data�� ��µ˴ϴ�\n");
        textcolor(10);
        for (int i = 0; i < strlen(buf); i++) {
            printf("%02X ", buf[i]);
        }//hexadecimal ���·� ���
        textcolor(7);
        printf("\n");


        //��ȣȭ�� ������ buf�� ��ȣȭ
        data_decryption(buf, strlen(buf));

        //���ڵ�->��ȣȭ�� ������ �������� ���
        strcpy(recv_msg, DEC);
        printf(" * �Ʒ��� Decoding-> Decryption ������ plain data�Դϴ�\n");
        textcolor(9);
        printf("%s\n", recv_msg);
        textcolor(7);
        printf("������������������������������������������������������������������������������������������������������������������������������������\n");

        //sock_array�� ����� ��� ���Ͽ� ����ĳ����. notify_client�Լ��� ��ȣȭ �� ���ڵ� ��� ���Ե�
        notify_client(recv_msg);
    }

    _endthreadex(0);
    return 0;
}

//Ŭ���̾�Ʈ�� �����ϴ� �Լ�. closesocket() �� WSACloseEvent()���� ����
void remove_client(int index)
{
    char remove_ip[256] = "\0";
    char send_msg[MAXBYTE] = "\0";
    memset(send_msg, '\0', MAXBYTE);
    strcpy(remove_ip, get_client_ip(index));
    printf("[TCP server] ����� ���� ���� (IP�ּ�: %s)\n", remove_ip);
    sprintf(send_msg, "[TCP server] ����� ���� ����\n");

    closesocket(sock_array[index].s);
    WSACloseEvent(sock_array[index].ev);

    total_socket_count--;
    sock_array[index].s = sock_array[total_socket_count].s;
    sock_array[index].ev = sock_array[total_socket_count].ev;

    notify_client(send_msg);
}

//Ŭ���̾�Ʈ�� IP�� ȹ���ϴ� �Լ�
char* get_client_ip(int index)
{
    static char ipaddress[256] = "\0";
    int addr_len;
    struct sockaddr_in sock;

    addr_len = sizeof(sock);
    if (getpeername(sock_array[index].s, (struct sockaddr*)&sock, &addr_len) < 0)
        return NULL;

    strcpy(ipaddress, inet_ntoa(sock.sin_addr));
    return ipaddress;
}


//�������� ��� Ŭ���̾�Ʈ���� �޼����� �����ִ� �Լ�(����ĳ����)
int notify_client(BYTE message[])
{
    BYTE server_msg[MAXBYTE] = "\0";
    memset(server_msg, '\0', MAXBYTE);
    data_encryption(message, strlen(message));
    strcpy(server_msg, base64_encode(ENC, strlen(ENC), &encoding_num));
    for (int i = 1; i < total_socket_count; i++)
        send(sock_array[i].s, server_msg, MAXBYTE, 0);
    return 0;
}
//�������� Ŭ���̾�Ʈ���� �޼����� ���� �� ���� ��ȣȭ �� ���ڵ� ������ ���ļ� ������.


//���� �Լ� ��������
int main()
{
    textcolor(14);
    server_setup();
    textcolor(7);

    unsigned int thread_id;
    BYTE server_msg[MAXBYTE] = "\0";
    BYTE input[MAXBYTE] = "\0";
    HANDLE mainthread;//�� ������ ����



    mainthread = (HANDLE)_beginthreadex(NULL, 0, chat, (void*)0, 0, &thread_id);
    if (mainthread)
    {
        while (1)
        {
            memset(server_msg, '\0', MAXBYTE);
            memset(input, '\0', MAXBYTE);

            strcpy(server_msg, "[TCP server] ");
            gets(input);//�������� Ŭ���̾�Ʈ���� ������ �޼��� �Է¹���
            if (strcmp(input, "/quit") == 0)
                break;
            strcat(server_msg, input);//���� �޼����� �������� �������
            notify_client(server_msg);//��ȣȭ+���ڵ� �� ����ĳ����
        }
        server_close();
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