
TOR_VER := 11.5.1

build: build-windows build-linux build-mac

build-windows: certutil/win64/certutil.exe.gz
	GOOS=windows go build -o truststore.exe ./bin/

build-linux: certutil/linux64/certutil.gz
	GOOS=linux go build -o truststore-linux ./bin/

build-mac: certutil/mac64/certutil.gz
	GOOS=darwin go build -o truststore-darwin ./bin/

clean:
	rm -rf certutil/

certutil/mac64/certutil.gz:
	mkdir -p certutil/mac64/
	cd certutil/mac64 \
		&& wget -nv https://dist.torproject.org/torbrowser/$(TOR_VER)/mar-tools-mac64.zip \
		&& unzip mar-tools-mac64.zip \
		&& cd mar-tools \
		&& mv certutil libnss3.dylib libmozglue.dylib .. \
		&& cd .. \
		&& rm -rf mar-tools* \
		&& gzip -9 *

certutil/linux64/certutil.gz:
	mkdir -p certutil/linux64/
	cd certutil/linux64 \
		&& wget -nv https://dist.torproject.org/torbrowser/$(TOR_VER)/mar-tools-linux64.zip \
		&& unzip mar-tools-linux64.zip \
		&& cd mar-tools \
		&& mv certutil libnspr4.so libplc4.so libplds4.so libnss3.so libnssutil3.so libsmime3.so libssl3.so .. \
		&& cd .. \
		&& rm -rf mar-tools* \
		&& gzip -9 *

certutil/win64/certutil.exe.gz:
	mkdir -p certutil/win64/
	cd certutil/win64 \
		&& wget -nv https://dist.torproject.org/torbrowser/$(TOR_VER)/mar-tools-win64.zip \
		&& unzip mar-tools-win64.zip \
		&& rm -f mar-tools-win64.zip \
		&& mv mar-tools/certutil.exe . \
		&& mv mar-tools/*.dll . \
		&& rm -rf mar-tools \
		&& gzip -9 *.exe *.dll
