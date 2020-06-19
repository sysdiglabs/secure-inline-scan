.PHONY: major minor patch release build push bump-git bump

VERSION=$(shell cat version)
IMAGE_NAME=sysdiglabs/secure-inline-scan

major:
	$(MAKE) release INCREMENT='major'

minor:
	$(MAKE) release INCREMENT='minor'

patch:
	$(MAKE) release INCREMENT='patch'

release:
	$(MAKE) bump INCREMENT=$(INCREMENT)
	$(MAKE) push

build:
	docker build -t $(IMAGE_NAME):$(VERSION) . --no-cache

push: build
	docker push $(IMAGE_NAME):$(VERSION)
	docker tag $(IMAGE_NAME):$(VERSION) $(IMAGE_NAME):latest
	docker push $(IMAGE_NAME):latest

bump-git:
	git add version
	git commit -m "Release $(VERSION)"
	git tag -m "Release $(VERSION)" -a "$(VERSION)"
	git push

bump:
	cat version | xargs npx semver -i $(INCREMENT) | tee version
	$(MAKE) bump-git
