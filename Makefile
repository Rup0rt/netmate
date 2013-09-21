all:
	gcc netmate.c -o netmate `pkg-config --cflags --libs gtk+-3.0` -Wall
