VERSION=$(shell cat version)

build:
	docker build --network=host -t sysdiglabs/secure_inline_scan:$(VERSION) .

push:
	docker push sysdiglabs/secure_inline_scan:$(VERSION)
	docker tag sysdiglabs/secure_inline_scan:$(VERSION) sysdiglabs/secure_inline_scan:latest
	docker push sysdiglabs/secure_inline_scan:latest
