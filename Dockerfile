# Copyright © 2024 chaoxin.lu
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

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