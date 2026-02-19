.PHONY: all clean deb

all:
	cd tquicd && go build -o tquicd .
	$(MAKE) -C ip-tquic

clean:
	rm -f tquicd/tquicd
	rm -f ../tquicd_*.deb
	$(MAKE) -C ip-tquic clean

install:
	$(MAKE) -C ip-tquic install

deb:
	dpkg-buildpackage -us -uc -b
