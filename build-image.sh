prefix=gzv-reg.piston.ink/library/auth
version="v1.1.0"

docker buildx build --platform linux/arm64 -f Dockerfile-Build -t "${prefix}"/oauth2-proxy:"${version}" . --push &&
docker buildx build --platform linux/arm64 -f Dockerfile-Build -t "${prefix}"/oauth2-proxy:latest . --push