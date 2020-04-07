VERSION=$(shell cat version)
IMAGE_NAME=sysdiglabs/secure-inline-scan

build:
	docker build --network=host -t $(IMAGE_NAME):$(VERSION) .

push:
	docker push $(IMAGE_NAME):$(VERSION)
	docker tag $(IMAGE_NAME):$(VERSION) $(IMAGE_NAME):latest
	docker push $(IMAGE_NAME):latest
