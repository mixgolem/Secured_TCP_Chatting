/*
* TCP ���� ä�� ���α׷� stack �ҽ�����
* �ۼ���: ������Ű��а� 20190895������, ������Ű��а� 20190954 ����ȯ
* �ۼ�ȯ�� : Visual Studio 2022
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <WinSock2.h>
#include <process.h>
#include <string.h>
#include <stdlib.h>

typedef char Element; // ����ȯ�� �����ϰ� �ϱ� ���� Element ����

typedef struct LinkedNode { // ��� ����ü(��Ʈ��ũ �뿪�� �����) 
	Element SECURED_IPADD[15]; // IP�� ���ڿ��μ� �����
	struct LinkedNode* link; // ����� link�μ� �ٸ� ����� �����
} Node;

Node* top = NULL; // stack�� top(�� �� ���������) ���� �� NULL�� �ʱ�ȭ

void error(char* str) // ���� �޽��� ��� �Լ�
{
	fprintf(stderr, "%s\n", str);
	exit(1);
};

/*���� ���� �Լ�*/
// ���� ���� �˻� �Լ� 
int is_empty() { return top == NULL; } // ���� �� ���� NULL���̸� ������� -> 1 ��ȯ 

// ���� �ʱ�ȭ �Լ�
void init_stack() { top = NULL; }

// ���� ũ�� ��ȯ �Լ�
int size()
{
	Node* p;
	int count = 0;
	for (p = top; p != NULL; p = p->link)
		count++; // top�������� ������ node�� link�� ���� �� ������ count
	return count;
}

// ���ÿ� ��Ҹ� �ִ� �Լ�
void push(Element* e)
{
	Node* p = (Node*)malloc(sizeof(Node));
	strcpy(p->SECURED_IPADD, e); // strcpy()�Լ� ����Ͽ� �Լ��� �μ��� ���� ���ڿ��� p ������ �ʵ忡 ����
	p->link = top; // push�� ��尡 ������ top�� �ǹǷ� link���� top�� ����
	top = p; // top�� push�� ����� p ����
}

// ���� ��Ҹ� �����ϰ� �� ���� ��ȯ�ϴ� �Լ�(���ڿ� ��ȯ)
void pop()
{
	Node* p;
	if (is_empty()) // ����������� �˻�
		error("���� ���� ����\n");
	p = top; // p�� top ����
	top = p->link; // top�� ��� ���� �� ���Ӱ� top�� �� ��Ҹ� ����Ű���� ��
	free(p);
}

// ���� ��� ���� ���� top�� �����͸� ��ȯ�ϴ� �Լ�(���ڿ� ��ȯ)
Element* peek()
{
	if (is_empty()) // ����������� �˻�
		error("���� ���� ����\n");
	return top->SECURED_IPADD; // top���� �������ʵ�(���ڿ�) ��ȯ
}

// ���� ���ִ� �Լ�
void destroy_stack()
{
	while (is_empty() == 0)
		pop(); // ������°� �� ������ pop();
}

// ���� ���� ������ ��� ����ϴ� �Լ�
void print_stack()
{
	Node* p;
	for (p = top; p != NULL; p = p->link)
		printf("%s\n", p->SECURED_IPADD); // p�� top�������� ��ũ�� ���� ������ �� ����� �����Ͱ�(���ڿ�)�� ���
}

// ���� ���� ������ ��� �˻��ϴ� �Լ�
Node* search_stack(char* isinstack)
{
	Node* p;
	for (p = top; p != NULL; p = p->link)
	{
		if (strcmp(isinstack, p->SECURED_IPADD) == 0)
			return p;
	}
	return NULL;
}// p�� top�������� ��ũ�� ���� �˻� �� ������ �ش� Node ��ȯ, ������ NULL ��ȯ

// ���� �� �����Ͱ� ���� ���������� ���°���� ��ȯ�ϴ� �Լ�
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
	return -1; // ������ ���� ��
}

// ���ϴ� IP�� POP�ϵ��� �ϴ� �Լ�
void search_pop(int count)
{
	if ((count - 1) != 0)
	{
		Node* p = top;
		Node* a;
		if (is_empty()) // ����������� �˻�
			error("���� ���� ����\n");

		for (int i = 1; i < count - 1; i++)
			p = p->link;
		a = p;
		for (int i = 0; i < 2; i++)
			a = a->link;
		p->link = a;
	}
	else if (count == 1)//top�� �ִ� �� �����ϰ������? 
		pop();
}