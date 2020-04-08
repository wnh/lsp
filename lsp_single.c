#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int bool;

typedef enum stype {
	INT,
	SYMBOL,
	PAIR,
	NIL
}stype;

typedef struct sexp sexp;
struct sexp {
	stype Type;
	union {
		int   Int;
		char *Symbol;
		struct {
			sexp *Car;
			sexp *Cdr;
		};
	};
};

typedef enum token_type {
	TOKEN_EOF,
	TOKEN_LPAREN,
	TOKEN_RPAREN,
	TOKEN_SYMBOL,
	TOKEN_INT,
} token_type;


typedef struct token {
	token_type Type;
	size_t     Start;
	size_t     Len;
} token;

typedef struct parser {
	const char *Data;
	size_t      DataLen;
	size_t      Pos;
	token   Token;
} parser;


/**************************************
                  DATA
 *************************************/
const sexp Nil_Data = {.Type = NIL };
sexp *Nil = (sexp*)&Nil_Data;

char *HumanTokenNames[]= {
	[TOKEN_EOF]    = "End of file",
	[TOKEN_LPAREN] = "(",
	[TOKEN_RPAREN] = ")",
	[TOKEN_SYMBOL] = "symbol",
	[TOKEN_INT]    = "integer",
	0
};

/**************************************
                  DEFS
 *************************************/
/* Lexer */
token_type LexNextToken(parser *P);
token_type LexSymbol(parser *P);
token_type LexNumber(parser *P);
void SkipWhitespace(parser *P);
bool IsSymbolStart(char C);
bool IsSymbol(char C);
bool IsAlpha(char C);
bool IsNumber(char C);
bool ContainsChar(char C, char *Set);
token *AllocToken(parser *P);

/* Parser */
token *PeekToken(parser *Parser);
sexp *ParseBuffer(const char* Buf);
sexp *ParseExpr(parser *P);
sexp *ParseList(parser *P);
sexp *NewSexp(stype Type);
char *SliceString(const char* Buffer, size_t Start, size_t Len);
void ExpectToken(parser *P, token_type Type);
void EatToken(parser *);
token *PeekToken(parser *);

void PrintSexp(sexp *Exp);

/* Util */
void *xmalloc(size_t);
void *xrealloc(void*, size_t);
/**************************************
               TESTING
 *************************************/

const char *TestProgs[];
void _RunTests();
void _TestLexer();

/**************************************
                IMPL
 *************************************/
token_type LexNextToken(parser *P)
{
#define NEXTC P->Data[P->Pos]
	for (;;) {
		SkipWhitespace(P);
		if (P->Pos == P->DataLen) {
			P->Token.Type = TOKEN_EOF;
			return TOKEN_EOF;
		}
		if(NEXTC == '(') {
			token_type T = TOKEN_LPAREN;
			P->Token.Type = T;
			P->Token.Start = P->Pos;
			P->Token.Len   = 1;
			P->Pos++;
			return T;
		} else if(NEXTC == ')') {
			token_type T = TOKEN_RPAREN;
			P->Token.Type = T;
			P->Token.Start = P->Pos;
			P->Token.Len   = 1;
			P->Pos++;
			return T;
		} else if(IsSymbolStart(NEXTC)) {
			return LexSymbol(P);
		} else if(IsNumber(NEXTC)) {
			return LexNumber(P);
		} else {
			printf("Unknown token: '%c' (0x%0hhx)\n", NEXTC, NEXTC);
			exit(1);
		}
	}
#undef NEXTC
}

token_type LexSymbol(parser *P)
{
	P->Token.Type = TOKEN_SYMBOL;
	P->Token.Start = P->Pos;
	P->Token.Len   = 0;
	while(IsSymbol(P->Data[P->Pos]))
	{
		P->Pos++;
		P->Token.Len++;
	}
	return P->Token.Type;
}

token_type LexNumber(parser *P)
{
	P->Token.Type = TOKEN_INT;
	P->Token.Start = P->Pos;
	P->Token.Len   = 0;
	while(IsNumber(P->Data[P->Pos]))
	{
		P->Pos++;
		P->Token.Len++;
	}
	return P->Token.Type;
}

bool IsSymbolStart(char C) { return (IsAlpha(C) || ContainsChar(C, "!@#$%^&*-+")); }
bool IsSymbol(char C) { return IsSymbolStart(C) || IsNumber(C); }
bool IsAlpha(char C)  { return ((C >= 'a') && (C <= 'z')) || ((C >= 'A') && (C <= 'Z')); }
bool IsNumber(char C) { return (C >= '0') && (C <= '9');}

bool ContainsChar(char C, char *Set)
{
	for (int i=0; Set[i]; i++)
	{
		if (Set[i] == C) return 1;
	}
	return 0;
}

void SkipWhitespace(parser *P)
{
	while(ContainsChar(P->Data[P->Pos], " \t\n\r"))
	{
		P->Pos++;
	}
}

sexp *ParseBuffer(const char* Buf)
{
	parser Parser = {};
	Parser.Data = Buf;
	Parser.DataLen = strlen(Parser.Data);
	Parser.Pos = 0;
	Parser.Token.Type  = 0;
	Parser.Token.Start = 0;
	Parser.Token.Len   = 0;
	EatToken(&Parser);

	for(;;)
	{
		sexp *Exp = ParseExpr(&Parser);
		if (!Exp) {
			//printf("ParseExpr() = NIL\n");
			break;
		}
		printf("ParseExpr() = %p\n", Exp);
		PrintSexp(Exp);
		printf("\n");
	}
	return NULL;
}

sexp *ParseExpr(parser *P)
{
	token *Tok = PeekToken(P);

	sexp *Ret = NULL;

	switch(Tok->Type) {
	case TOKEN_LPAREN:
		return ParseList(P);
	case TOKEN_SYMBOL:
		{
			Ret = NewSexp(SYMBOL);
			Ret->Symbol = SliceString(
				P->Data,
				P->Token.Start,
				P->Token.Len
			);
			EatToken(P);
			break;
		}
	case TOKEN_INT:
		{
			Ret = NewSexp(INT);
			char *IntStr = SliceString(
				P->Data,
				P->Token.Start,
				P->Token.Len
			);
			Ret->Int = atoi(IntStr);
			free(IntStr);
			EatToken(P);
			break;
		}
	case TOKEN_EOF:
		break;
	default:
		printf("ParseError: unknown token\n");
		exit(1);
	}
	return Ret;
}
sexp *ParseList(parser *P)
{
	ExpectToken(P, TOKEN_LPAREN);
	sexp *Head = Nil;
	sexp *Tail = Nil;
	for(;;)
	{
		token *Tok = PeekToken(P);
		if(Tok->Type == TOKEN_RPAREN) { break; }

		sexp *Sx = NewSexp(PAIR);
		sexp *Data = ParseExpr(P);
		if(!Data) {
			printf("ParseError: unable to parse expression\n");
			return NULL;
		}
		Sx->Car = Data;
		Sx->Cdr = Nil;
		if (Head == Nil) {
			Head = Tail = Sx;
		} else {
			Tail->Cdr = Sx;
			Tail = Sx;
		}
	}
	ExpectToken(P, TOKEN_RPAREN);
	return Head;
}


token *PeekToken(parser *Parser)
{
	return &Parser->Token;
}
void EatToken(parser *Parser)
{
	token_type Tp = LexNextToken(Parser);
}

void ExpectToken(parser *Parser, token_type Type)
{
	if(Parser->Token.Type != Type) {
		printf("Parse Error: expeced %s;", HumanTokenNames[Type]);
		exit(1);
	}
	EatToken(Parser);
}

int main(int argc, char **argv)
{
	_RunTests();
	return 0;

}


void _RunTests()
{
	_TestLexer();

	for(int i=0; TestProgs[i] != 0; i++)
	{
		printf("Parsing: %s\n", TestProgs[i]);
		ParseBuffer(TestProgs[i]);
	}
}

sexp *NewSexp(stype Type)
{
	sexp *S = xmalloc(sizeof(sexp));
	if(!S) {
		printf("NewSexp: xmalloc fail");
		exit(1);
	}
	S->Type = Type;
	return S;
}

char *SliceString(const char* Buffer, size_t Start, size_t Len)
{
	char *Str = xmalloc(Len+1);
	memcpy(Str, &Buffer[Start], Len);
	Str[Len] = 0;
	return Str;
}

void PrintSexp(sexp *Exp)
{
	switch(Exp->Type) {
	case INT:
		printf("%d", Exp->Int);
		break;
	case SYMBOL:
		printf("%s", Exp->Symbol);
		break;
	case NIL:
		printf("Nil");
		break;
	case PAIR: {
		printf("(");
		sexp *E = Exp;
		for (;;){
			if(E == Nil) break;
			PrintSexp(E->Car);
			printf(" ");
			E = E->Cdr;
		}
		printf(")");
	} break;
	default:
		assert(0);
	}
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if(!ret) {
		fprintf(stderr, "xmalloc failed\n");
		exit(1);
	}
	return ret;
}

void *xrealloc(void* ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if(!ret) {
		fprintf(stderr, "xrealloc failed\n");
		exit(1);
	}
	return ret;
}

/* TEST */
void _TestLexer()
{
	parser P;
#define InitLex(Str) P.Data = (Str); \
	P.DataLen = strlen(Str);\
	P.Pos = 0; \
	P.Token.Type = 0; \
	P.Token.Start = 0; \
	P.Token.Len = 0;

#define AssertInt() LexNextToken(&P); assert(P.Token.Type == TOKEN_INT);
#define AssertType(t) LexNextToken(&P); assert(P.Token.Type == (t));

	InitLex("123");
	AssertInt();
	AssertType(TOKEN_EOF);

	InitLex("not-a-real-thing")
	AssertType(TOKEN_SYMBOL);
	AssertType(TOKEN_EOF);

	InitLex("*global*")
	AssertType(TOKEN_SYMBOL);
	AssertType(TOKEN_EOF);

	InitLex("+")
	AssertType(TOKEN_SYMBOL);
	AssertType(TOKEN_EOF);

	InitLex("+123")
	AssertType(TOKEN_SYMBOL);
	AssertType(TOKEN_EOF);

	InitLex("((()");
	AssertType(TOKEN_LPAREN);
	AssertType(TOKEN_LPAREN);
	AssertType(TOKEN_LPAREN);
	AssertType(TOKEN_RPAREN);
	AssertType(TOKEN_EOF);

#undef init
#undef AssertInt
#undef AssertType
}
const char *TestProgs[] = {
	" (+ 1 2)",
	"((1) (2))",
	"(define (square-plus-n x) (+ (* x x) 123))",
	"()",
	"(define (x ",
	0
};
