/*
* TCP 보안 채팅 프로그램 stack 소스파일
* 작성자: 정보통신공학과 20190895김찬영, 정보통신공학과 20190954 허진환
* 작성환경 : Visual Studio 2022
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <WinSock2.h>
#include <process.h>
#include <string.h>
#include <stdlib.h>

typedef char Element; // 형변환을 용이하게 하기 위해 Element 정의

typedef struct LinkedNode { // 노드 구조체(네트워크 대역이 저장됨) 
	Element SECURED_IPADD[15]; // IP가 문자열로서 저장됨
	struct LinkedNode* link; // 노드의 link로서 다른 노드들과 연결됨
} Node;

Node* top = NULL; // stack의 top(맨 위 헤드포인터) 선언 및 NULL값 초기화

void error(char* str) // 에러 메시지 출력 함수
{
	fprintf(stderr, "%s\n", str);
	exit(1);
};

/*스택 연산 함수*/
// 스택 공백 검사 함수 
int is_empty() { return top == NULL; } // 스택 맨 위가 NULL값이면 공백상태 -> 1 반환 

// 스택 초기화 함수
void init_stack() { top = NULL; }

// 스택 크기 반환 함수
int size()
{
	Node* p;
	int count = 0;
	for (p = top; p != NULL; p = p->link)
		count++; // top에서부터 시작한 node가 link를 따라 갈 때마다 count
	return count;
}

// 스택에 요소를 넣는 함수
void push(Element* e)
{
	Node* p = (Node*)malloc(sizeof(Node));
	strcpy(p->SECURED_IPADD, e); // strcpy()함수 사용하여 함수의 인수로 받은 문자열을 p 데이터 필드에 복사
	p->link = top; // push된 노드가 스택의 top이 되므로 link값에 top값 대입
	top = p; // top에 push된 요소인 p 대입
}

// 스택 요소를 삭제하고 그 값을 반환하는 함수(문자열 반환)
void pop()
{
	Node* p;
	if (is_empty()) // 공백상태인지 검사
		error("스택 공백 에러\n");
	p = top; // p애 top 대입
	top = p->link; // top이 요소 삭제 후 새롭게 top이 될 요소를 가리키도록 함
	free(p);
}

// 스택 요소 삭제 없이 top의 데이터를 반환하는 함수(문자열 반환)
Element* peek()
{
	if (is_empty()) // 공백상태인지 검사
		error("스택 공백 에러\n");
	return top->SECURED_IPADD; // top값의 데이터필드(문자열) 반환
}

// 스택 없애는 함수
void destroy_stack()
{
	while (is_empty() == 0)
		pop(); // 공백상태가 될 때까지 pop();
}

// 스택 안의 데이터 요소 출력하는 함수
void print_stack()
{
	Node* p;
	for (p = top; p != NULL; p = p->link)
		printf("%s\n", p->SECURED_IPADD); // p가 top에서부터 링크를 따라가 끝까지 각 노드의 데이터값(문자열)을 출력
}

// 스택 안의 데이터 요소 검색하는 함수
Node* search_stack(char* isinstack)
{
	Node* p;
	for (p = top; p != NULL; p = p->link)
	{
		if (strcmp(isinstack, p->SECURED_IPADD) == 0)
			return p;
	}
	return NULL;
}// p가 top에서부터 링크를 따라가 검색 후 있으면 해당 Node 반환, 없으면 NULL 반환

// 스택 안 데이터가 제일 위에서부터 몇번째인지 반환하는 함수
int search_num(char* buf)
{
	int count = 0;
	Node* p;
	for (p = top; p != NULL; p = p->link)
	{
		count++;
		if (!strcmp(buf, p->SECURED_IPADD))
			return count;


	}
	return -1; // 데이터 없을 때
}

// 원하는 IP만 POP하도록 하는 함수
void search_pop(int count)
{
	if ((count - 1) != 0)
	{
		Node* p = top;
		Node* a;
		if (is_empty()) // 공백상태인지 검사
			error("스택 공백 에러\n");

		for (int i = 1; i < count - 1; i++)
			p = p->link;
		a = p;
		for (int i = 0; i < 2; i++)
			a = a->link;
		p->link = a;
	}
	else if (count == 1)//top에 있는 걸 삭제하고싶으면? 
		pop();
}