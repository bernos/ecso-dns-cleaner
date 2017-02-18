DOCKER_IMAGE := bernos/ecso-dns-cleaner

docker.build:
	docker build -t bernos/ecso-dns-cleaner .

docker.push: docker.build
	docker tag "$(DOCKER_IMAGE)" "$(DOCKER_IMAGE):latest"
	docker push "$(DOCKER_IMAGE):latest"
