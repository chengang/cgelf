elf-parser:
	clang -Wall -Wno-format cgelf.c elf-parser.c -g -o elf-parser
	clang -shared -fPIC -o libdog.so dog.c
	./elf-parser ./libdog.so
link:
	clang -Wall -Wno-format cgelf.c ivory.c ivory_linker.c -g -o ivory-linker
	clang -shared -fPIC -o libdog.so dog.c
	./ivory-linker ./libdog.so
clean:
	rm -frv libdog.so elf-parser ivory-linker

.PHONY: all test build dog
