
TOR_VER := 11.5.1
TOR_URL := https://dist.torproject.org/torbrowser/$(TOR_VER)/mar-tools-win64.zip

build-windows: certutil/win64/certutil.exe.gz
	GOOS=windows go build -o truststore.exe ./bin/

clean:
	rm -rf certutil/

certutil/win64/certutil.exe.gz:
	mkdir -p certutil/win64/
	cd certutil/win64 \
		&& wget -nv $(TOR_URL) \
		&& unzip mar-tools-win64.zip \
		&& rm -f mar-tools-win64.zip \
		&& mv mar-tools/certutil.exe . \
		&& mv mar-tools/*.dll . \
		&& rm -rf mar-tools \
		&& gzip -9 *.exe *.dll
