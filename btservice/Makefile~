CC=gcc
CFLAGS=-Wall -g
LDFLAGS=-lcurl -lconfig -lbluetooth
SOURCES=btservice.c
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=btservice

all: $(SOURCES) $(EXECUTABLE) 
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) $(CFLAGS) -g -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(EXECUTABLE)

install:
	cp bluetooth /etc/insserv.conf.d/
	cp btservice.sh /etc/init.d
	cp btservice.cfg /etc/
	cp btservice /usr/sbin/
	insserv -d /etc/init.d/btservice.sh

prepare:
	apt-get install libcurl4-gnuttls-dev libconfig-dev
