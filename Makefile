CXX=g++
INSTALL=install
#CFLAGS=-Wall -O3
CFLAGS=-Wall -g
CFLAGS+=`pkg-config --cflags --libs apr-1 apr-util-1 ImageMagick++ libmemcached`

TARGET=mod_resizeimage.so
TARGETDIR=/usr/lib/httpd/modules/

SRC=mod_resizeimage.cpp
HEADERS=

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(CXX) -shared -fPIC $(CFLAGS) -o $(TARGET) $(SRC)

install: $(TARGET)
	sudo $(INSTALL) $(TARGET) $(TARGETDIR)

clean:
	@rm -f $(TARGET)

check:
	@echo CFLAGS=$(CFLAGS)
	$(CXX) $(CFLAGS) -o $(TARGET:.so=) $(SRC)
