# 运行阶段指定alpine作为基础镜像
FROM alpine

LABEL maintainer="chaoxin.lu"

WORKDIR /app

# 将上一个阶段app文件夹下的所有文件复制进来
COPY main /app/main


# 指定运行时环境变量
ENV GIN_MODE=release \
    SERVER_PORT=6666

ENTRYPOINT ["./main"]