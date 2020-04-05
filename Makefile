all:
	clang -g -o lsp_single lsp_single.c

run: all
	gdb -q -ex run ./lsp_single

debug: all
	gdb -q ./lsp_single

.PHONY: all debug run
