.PHONY: all clean deb

all:
	cd tquicd && go build -o tquicd .

clean:
	rm -f tquicd/tquicd
	rm -f ../tquicd_*.deb

deb:
	dpkg-buildpackage -us -uc -b
