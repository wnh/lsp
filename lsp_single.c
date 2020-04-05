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
		} Pair;
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

typedef struct lexer {
	const char *Data;
	size_t      DataLen;
	size_t      Pos;
	size_t      TokenStart;
	size_t      TokenLen;
} lexer;


typedef struct parser {
	lexer   Lex;
	token   CurToken;
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
void SkipWhitespace(lexer *Lex);
token_type LexSymbol(lexer *Lex);
token_type LexNumber(lexer *Lex);
bool IsSymbolStart(char C);
bool IsSymbol(char C);
bool IsAlpha(char C);
bool IsNumber(char C);
bool ContainsChar(char C, char *Set);
token *AllocToken(parser *P);
token_type LexNextToken(lexer *Lex);

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

/**************************************
                IMPL
 *************************************/
token_type LexNextToken(lexer *Lex)
{
#define NEXTC Lex->Data[Lex->Pos]
	for (;;) {
		printf("LexNextToken(pos=%ld, len=%ld)\n", Lex->Pos, Lex->DataLen);
		SkipWhitespace(Lex);
		if (Lex->Pos == Lex->DataLen) {
			return TOKEN_EOF;
		}
		if(NEXTC == '(') {
			token_type T = TOKEN_LPAREN;
			Lex->TokenStart = Lex->Pos;
			Lex->TokenLen   = 1;
			Lex->Pos++;
			return T;
		} else if(NEXTC == ')') {
			token_type T = TOKEN_RPAREN;
			Lex->TokenStart = Lex->Pos;
			Lex->TokenLen   = 1;
			Lex->Pos++;
			return T;
		} else if(IsSymbolStart(NEXTC)) {
			return LexSymbol(Lex);
		} else if(IsNumber(NEXTC)) {
			return LexNumber(Lex);
		} else {
			printf("Unknown token: '%c' (0x%0hhx)\n", NEXTC, NEXTC);
			exit(1);
		}
	}
#undef NEXTC
}

token_type LexSymbol(lexer *Lex)
{
	Lex->TokenStart = Lex->Pos;
	Lex->TokenLen   = 0;
	while(IsSymbol(Lex->Data[Lex->Pos]))
	{
		Lex->Pos++;
		Lex->TokenLen++;
	}
	return TOKEN_SYMBOL;
}

token_type LexNumber(lexer *Lex)
{
	Lex->TokenStart = Lex->Pos;
	Lex->TokenLen   = 0;
	while(IsNumber(Lex->Data[Lex->Pos]))
	{
		Lex->Pos++;
		Lex->TokenLen++;
	}
	return TOKEN_INT;
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

void SkipWhitespace(lexer *Lex)
{
	while(ContainsChar(Lex->Data[Lex->Pos], " \t\n\r"))
	{
		Lex->Pos++;
	}
}

sexp *ParseBuffer(const char* Buf)
{
	parser Parser = {};
	Parser.Lex.Data = Buf;
	Parser.Lex.DataLen = strlen(Parser.Lex.Data);
	Parser.Lex.Pos = 0;
	Parser.CurToken.Type  = 0;
	Parser.CurToken.Start = 0;
	Parser.CurToken.Len   = 0;
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
				P->Lex.Data,
				P->CurToken.Start,
				P->CurToken.Len
			);
			EatToken(P);
			break;
		}
	case TOKEN_INT:
		{
			Ret = NewSexp(INT);
			char *IntStr = SliceString(
				P->Lex.Data,
				P->CurToken.Start,
				P->CurToken.Len
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
		Sx->Pair.Car = Data;
		Sx->Pair.Cdr = Nil;
		if (Head == Nil) {
			Head = Tail = Sx;
		} else {
			Tail->Pair.Cdr = Sx;
			Tail = Sx;
		}
		//	Head = NewSexp(PAIR);
		//	Head->Pair.Cdr = Nil;
		//	Tail = Head;
		//}
		//Sx->Pair.Car = TmpCar;
		//sexp *TmpCar = ParseExpr(P);
		//Tail->Pair.Cdr = Sx;
		//Tail = Sx;
		//EatToken(P);
	}
	ExpectToken(P, TOKEN_RPAREN);
	return Head;
}


token *PeekToken(parser *Parser)
{
	return &Parser->CurToken;
}
void EatToken(parser *Parser)
{
	token_type Tp = LexNextToken(&Parser->Lex);
	//TODO copy into Parser->CurToken
	Parser->CurToken.Type  = Tp;
	Parser->CurToken.Start = Tp;
	Parser->CurToken.Start = Parser->Lex.TokenStart;
	Parser->CurToken.Len   = Parser->Lex.TokenLen;
}

void ExpectToken(parser *Parser, token_type Type)
{
	if(Parser->CurToken.Type != Type) {
		printf("Parse Error: expeced %s;", HumanTokenNames[Type]);
		exit(1);
	}
	EatToken(Parser);
}

int main(int argc, char **argv)
{
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
			PrintSexp(E->Pair.Car);
			printf(" ");
			E = E->Pair.Cdr;
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

/* TEST DATA */
const char *TestProgs[] = {
	" (+ 1 2)",
	"((1) (2))",
	"(define (square-plus-n x) (+ (* x x) 123))",
	"()",
	0
};
