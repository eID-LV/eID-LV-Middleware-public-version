PREFIX ?= /opt/latvia-eid
FULLNAME = eidlv_engine.so
CXX="gcc"

CXXFLAGSBASE =  -DNDEBUG -I. -I../openssl/include -O2 -D_REENTRANT -DLATVIAEID_PREFIX="\"$(PREFIX)\""

CXXFLAGS = -fPIC $(CXXFLAGSBASE)

LDFLAGS = -Wl,-rpath,/opt/latvia-eid/lib -L../openssl/lib -lssl -lcrypto -ldl -Wl,--version-script=eidlv_engine.exports -Wl,--no-undefined -shared 

SRCS = eng_back.c eng_err.c eng_front.c eng_parse.c libpkcs11.c p11_atfork.c p11_attr.c p11_cert.c p11_ckr.c p11_ec.c p11_err.c p11_front.c p11_key.c p11_load.c p11_misc.c p11_pkey.c p11_rsa.c p11_slot.c
OBJECTS = $(SRCS:.c=.o)

#######################
# don't modify
#######################
libdir = $(PREFIX)/lib

all: $(FULLNAME)

$(FULLNAME): $(OBJECTS)
	$(CXX) -o $(FULLNAME) $(OBJECTS) $(LDFLAGS) 

	
-include $(OBJECTS:.o=.d)

.c.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@
	$(CXX) -MM $(CXXFLAGSBASE) $*.c > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

install: all
	mkdir -p $(libdir)
	cp -R $(FULLNAME) $(libdir)/.
	
uninstall:
	rm -fr $(libdir)/$(FULLNAME)
	
.PHONY: clean uninstall install
clean:
	rm -fr *.o *.d
	rm -fr $(FULLNAME)


