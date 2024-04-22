a.out: main.c
    gcc -o a.out main.c -lssl -lcrypto

clean:
    rm -f a.out
