.PHONY: major minor patch release build push bump-git bump

VERSION=$(shell cat version)
IMAGE_NAME=sysdiglabs/secure-inline-scan
INLINE_SCAN_SCRIPT=inline_scan.sh

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
	git push --follow-tags

bump:
	cat version | xargs npx semver -i $(INCREMENT) | tee version
	$(MAKE) bump-git

shellcheck:
	docker run --rm \
		--mount type=bind,source=$(PWD)/$(INLINE_SCAN_SCRIPT),target=/$(INLINE_SCAN_SCRIPT) \
		koalaman/shellcheck \
		-- /$(INLINE_SCAN_SCRIPT)
