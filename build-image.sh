prefix=gzv-reg.piston.ink/library/auth
version="v1.2.1"

docker buildx build --platform linux/arm64,linux/amd64 -f Dockerfile-Build -t "${prefix}"/oauth2-proxy:"${version}" . --push &&
docker buildx build --platform linux/arm64,linux/amd64 -f Dockerfile-Build -t "${prefix}"/oauth2-proxy:latest . --push