#prefix=gzv-reg.xyz.com/library/auth
prefix=gzv-reg.piston.ink/library
version="v1.2.0"

docker buildx build --platform linux/amd64 -f Dockerfile-Build -t "${prefix}"/oauth2-proxy:"${version}" . --push &&
docker buildx build --platform linux/amd64 -f Dockerfile-Build -t "${prefix}"/oauth2-proxy:latest . --push
