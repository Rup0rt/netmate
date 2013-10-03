all:
	gcc netmate.c -o netmate -Wall -Wextra -pedantic `pkg-config --cflags --libs gtk+-3.0` -lpcap
