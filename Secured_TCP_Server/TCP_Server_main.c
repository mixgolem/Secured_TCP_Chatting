/*
* TCP 보안 채팅 프로그램 server 소스파일
* 작성자: 정보통신공학과 20190895김찬영, 정보통신공학과 20190954 허진환
* 작성환경 : Visual Studio 2022
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
#define MAXCLIENT 10    //최대 클라이언트 수 제한
#define PORTNUM 9000    //서버 Port번호


//콘솔에 출력되는 메세지에 색상코드를 부여함
void textcolor(int colorNum) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colorNum);
}


//base64 인코딩, 디코딩에 필요한 함수 및 변수
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



//암호화, 복호화에 필요한 변수
extern int length;          //암호화할 문자열의 길이
extern BYTE ENC[MAXBYTE];   //암호화 함수 사용시 ENC에 암호화된 내용 저장
extern BYTE DEC[MAXBYTE];   //복호화 함수 사용시 DEC에 복호화된 내용 저장


//TCP서버 동작에 관련된 사용자 정의 함수
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
//소켓에 HANDLE event를 포함하여 구조체 선언
typedef struct sock_info {
    SOCKET s;
    HANDLE ev;
} SOCK_INFO;

SOCK_INFO sock_array[MAXCLIENT + 1];    //소켓 배열을 선언
int total_socket_count = 0;             //초기 소켓 배열의 수 = 0



//인가된 IP만 접속을 가능하게 하기 위해 서버 시작 전 SETUP하는 함수
//서버 접근 허용 IP주소는 stack에 저장되어 관리된다 (stack함수는 stack.c에 저장)
//사용자 정의 함수 search_num()과 search_stack() 함수를 정의하여 스택이지만 pop 이외의 원하는 데이터의 삭제 연산을 추가하였음
void server_setup() {
    printf("[TCP server] 프로그램을 시작하려면 [ENTER]\n");
    int count = 0;
    while (1)       //사용자로부터 계속 입력받음
    {
        char command = NULL;
        char buffer[32];


        while (getchar() != '\n');//입력 버퍼 제거
        printf("[IP주소 추가/삭제] ([a] : add / [d] : delete / [s] : show IP add / [l] : listen) : ");
        scanf("%c", &command);
        if (command == 'a')
        {
            printf(">>추가할 IP주소 입력 : ");
            scanf("%s", buffer);
            if (search_stack(buffer) == NULL)
                push(buffer);
            else
                printf("중복된 IP주소입니다.\n");
        }
        else if (command == 'd')
        {
            printf(">>삭제할 IP주소 입력: ");
            scanf("%s", buffer);
            count = search_num(buffer);
            if (search_stack(buffer) != NULL)
            {
                search_pop(count);
                printf("%s가 삭제되었습니다\n", buffer);
            }
            else
                printf("저장되지 않은 IP입니다\n");
        }
        else if (command == 's')
        {
            printf("\n[인가된(스택에 저장된) IP주소]\n");
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            print_stack();
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            printf("\n");
        }
        else if (command == 'l')
        {
            while (getchar() != '\n');
            break;
        }
        else
        {
            printf("잘못 입력하셨습니다\n\n");
        }

    }
}

//서버 시작 시 서버를 초기화하는 단계
//winsock 초기화, server socket 생성, bind, listen 단계를 포함한다
int server_init()
{
    WSADATA wsadata;
    SOCKET s;
    SOCKADDR_IN server_address;

    memset(&sock_array, 0, sizeof(sock_array));
    total_socket_count = 0;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)//WINSOCK 초기화
    {
        puts("WSAStartup 에러.");//오류 발생 시 오류메세지 출력
        return -1;
    }

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)//SERVER SOCKET 생성
    {
        puts("socket 에러.");//오류 발생 시 오류메세지 출력
        return -1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORTNUM);//서버의 PORTNUMBER은 소스파일 최상단에 정의

    //bind 단계
    if (bind(s, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
    {
        puts("bind 에러");
        return -2;
    }


    //listen 단계
    if (listen(s, SOMAXCONN) < 0)
    {
        puts("listen 에러");
        return -3;
    }

    return s;
}

//서버 종료 시 sock_array에 저장된 모든 socket을 종료하고 이벤트 객체 핸들을 닫음
int server_close()
{
    for (int i = 1; i < total_socket_count; i++)
    {
        closesocket(sock_array[i].s);
        WSACloseEvent(sock_array[i].ev);
    }

    return 0;
}

//2개의 쓰레드 생성 후 병렬적으로 기능 수행
//서버 소켓 초기화 후 지속적으로 연결된 클라이언트로부터 수신할 이벤트가 있는지 이벤트를 모니터링(종료 전까지 기다림)
//이벤트에는 FD_ACCEPT(클라이언트 접속), FD_READ(메세지 수신), FD_CLOSE(클라이언트 접속 종료)
//서버에서 통신 및 채팅을 위한 사용자 정의 함수
unsigned int WINAPI chat(void* param)
{
    SOCKET  server_socket;
    WSANETWORKEVENTS ev;
    int index;
    WSAEVENT handle_array[MAXCLIENT + 1];

    server_socket = server_init();
    if (server_socket < 0)
    {
        printf("초기화 에러\n");
        exit(0);
    }
    else
    {
        printf("\n[TCP server] 서버 초기화 완료 (포트번호:%d) 클라이언트 접속을 대기\n", PORTNUM);

        HANDLE event = WSACreateEvent();//네트워크 이벤트 개체 생성
        sock_array[total_socket_count].ev = event;
        sock_array[total_socket_count].s = server_socket;

        WSAEventSelect(server_socket, event, FD_ACCEPT);
        total_socket_count++;

        while (1)
        {
            memset(&handle_array, 0, sizeof(handle_array));
            for (int i = 0; i < total_socket_count; i++)
                handle_array[i] = sock_array[i].ev;

            index = WSAWaitForMultipleEvents(total_socket_count,//이벤트 객체가 신호 상태가 되기를 기다린다
                handle_array, FALSE, INFINITE, FALSE);
            if ((index != WSA_WAIT_FAILED) && (index != WSA_WAIT_TIMEOUT))
            {
                WSAEnumNetworkEvents(sock_array[index].s, sock_array[index].ev, &ev);//발생한 네트워크 이벤트를 알아내고, 적절한 소켓 함수 호출 후 처리
                if (ev.lNetworkEvents == FD_ACCEPT)//클라이언트 접속 이벤트 감지시 add_client
                    add_client(index);
                else if (ev.lNetworkEvents == FD_READ)//클라이언트가 메세지 보냈을 경우 read_client
                    read_client(index);
                else if (ev.lNetworkEvents == FD_CLOSE)//클라이언트 접속 종료시 remove_client
                    remove_client(index);
            }
        }
        closesocket(server_socket);
    }

    WSACleanup();
    _endthreadex(0);

    return 0;

}

//WSAeventselect모델(교재 10.4장 402pg)
//ACCEPT후 소켓 및 이벤트를 사용자 정의한 SOCK_INFO 배열에 저장
//클라이언트 접속 이벤트 발생했을 경우 실행되는 함수
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
            printf("\n[TCP server] 인가되지 않은 IP 접속 시도 (IP주소: %s, port: %d)\n",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            textcolor(7);
            sprintf(msg, "\n[TCP server] 인가되지 않은 IP 접속 시도 (IP주소: %s, port: %d)\n",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            notify_client(msg);
            closesocket(accept_sock);   //우선 모든 클라이언트에 대해서 accept한 다음, IP주소를 읽어와 stack안의 IP와 비교하여 없을 경우 소켓 닫으며 접속을 차단함
            return 1;
        }
        else {
            HANDLE event = WSACreateEvent();//인가된 IP가 접속했을 경우 이벤트 생성
            sock_array[total_socket_count].ev = event;
            sock_array[total_socket_count].s = accept_sock;

            WSAEventSelect(accept_sock, event, FD_READ | FD_CLOSE);//소켓 이벤트를 모니터하기 위해 FD_READ및 FD_CLOSE 이벤트를 등록

            total_socket_count++;
            printf("[TCP server] 새로운 사용자 접속 (IP주소: %s)\n", inet_ntoa(addr.sin_addr));


            sprintf(msg, "[TCP server] 새로운 사용자 접속\n");
            notify_client(msg);
        }

    }

    return 0;
}


//쓰레드를 추가적으로 생성해서 클라이언트가 송신한 메세지를 수신하고 수신한 메세지를 각 클라이언트들에게 전송한다
int read_client(int index)
{
    unsigned int tid;
    HANDLE mainthread = (HANDLE)_beginthreadex(NULL, 0, recv_and_forward, (void*)index, 0, &tid);
    WaitForSingleObject(mainthread, INFINITE);

    CloseHandle(mainthread);

    return 0;
}

//send는 encryption 후 encoding, recv는 decoding 후 decryption
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



    //CLIENT 메세지 입력->CLIENT 암호화->CLIENT 인코딩->CLIENT에서 전송->
    //SERVER 수신->SERVER 디코딩->SERVER 복호화
    //SERVER 암호화->SERVER 인코딩->SERVER에서 전송->모든 CLIENT에게
    //클라이언트로부터 받은 데이터는 암호화된 후 인코딩되었음
    recv_len = recv(sock_array[index].s, recv_msg, MAXBYTE, 0);
    if (recv_len > 0)
    {
        addr_len = sizeof(client_address);
        getpeername(sock_array[index].s, (SOCKADDR*)&client_address, &addr_len);

        //클라이언트로부터 받은 메세지를 디코딩(base64_decode) 해서 buf에 저장
        strcpy(buf, base64_decode(recv_msg, strlen(recv_msg), &decoding_num));

        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf(" * Client recv()로 받은 Encoded+Encrypted data입니다\n");
        textcolor(6);
        printf("%s\n", recv_msg);
        textcolor(7);
        printf(" * 이후 Decoding하면, Encrypted data가 출력됩니다\n");
        textcolor(10);
        for (int i = 0; i < strlen(buf); i++) {
            printf("%02X ", buf[i]);
        }//hexadecimal 형태로 출력
        textcolor(7);
        printf("\n");


        //암호화된 상태의 buf를 복호화
        data_decryption(buf, strlen(buf));

        //디코딩->복호화된 내용을 서버에서 출력
        strcpy(recv_msg, DEC);
        printf(" * 아래는 Decoding-> Decryption 이후의 plain data입니다\n");
        textcolor(9);
        printf("%s\n", recv_msg);
        textcolor(7);
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        //sock_array에 저장된 모든 소켓에 유니캐스팅. notify_client함수에 암호화 및 인코딩 기능 포함됨
        notify_client(recv_msg);
    }

    _endthreadex(0);
    return 0;
}

//클라이언트를 제거하는 함수. closesocket() 및 WSACloseEvent()과정 포함
void remove_client(int index)
{
    char remove_ip[256] = "\0";
    char send_msg[MAXBYTE] = "\0";
    memset(send_msg, '\0', MAXBYTE);
    strcpy(remove_ip, get_client_ip(index));
    printf("[TCP server] 사용자 접속 종료 (IP주소: %s)\n", remove_ip);
    sprintf(send_msg, "[TCP server] 사용자 접속 종료\n");

    closesocket(sock_array[index].s);
    WSACloseEvent(sock_array[index].ev);

    total_socket_count--;
    sock_array[index].s = sock_array[total_socket_count].s;
    sock_array[index].ev = sock_array[total_socket_count].ev;

    notify_client(send_msg);
}

//클라이언트의 IP를 획득하는 함수
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


//서버에서 모든 클라이언트에게 메세지를 보내주는 함수(유니캐스팅)
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
//서버에서 클라이언트에게 메세지를 보낼 때 또한 암호화 및 인코딩 과정을 거쳐서 보낸다.


//메인 함수 시작지점
int main()
{
    textcolor(14);
    server_setup();
    textcolor(7);

    unsigned int thread_id;
    BYTE server_msg[MAXBYTE] = "\0";
    BYTE input[MAXBYTE] = "\0";
    HANDLE mainthread;//주 스레드 생성



    mainthread = (HANDLE)_beginthreadex(NULL, 0, chat, (void*)0, 0, &thread_id);
    if (mainthread)
    {
        while (1)
        {
            memset(server_msg, '\0', MAXBYTE);
            memset(input, '\0', MAXBYTE);

            strcpy(server_msg, "[TCP server] ");
            gets(input);//서버에서 클라이언트에게 공지할 메세지 입력받음
            if (strcmp(input, "/quit") == 0)
                break;
            strcat(server_msg, input);//공지 메세지의 형식으로 만들어줌
            notify_client(server_msg);//암호화+인코딩 후 유니캐스팅
        }
        server_close();
        WSACleanup();
        CloseHandle(mainthread);
    }

    return 0;
}







//base64인코딩 및 디코딩 관련 함수
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