CC=gcc
CFLAGS=-Wall
LDFLAGS=-lcurl -lconfig -lbluetooth
SOURCES=ble-service.c
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=ble-service

all: $(SOURCES) $(EXECUTABLE) 
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) $(CFLAGS) -g -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(EXECUTABLE)

install:
	cp bluetooth /etc/insserv.conf.d/
	cp ble-service.sh /etc/init.d
	cp ble-service.cfg /etc/
	cp ble-service /usr/sbin/
	insserv -d /etc/init.d/ble-service.sh

prepare:
	apt-get install libcurl4-openssl-dev libconfig-dev
