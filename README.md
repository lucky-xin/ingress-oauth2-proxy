# Ingress Oauth2 Proxy

## Getting started

--------------------------------

### 1.JWT token校验

#### 1.1 JWT token校验——本地解析token

![实现思路](.img/parse-jwt-with-key.png)

### 环境变量配置

| 名称                     | 描述                                                                | 必填 | 默认值                                    |
|------------------------|-------------------------------------------------------------------|----|----------------------------------------
| `OAUTH2_TOKEN_KEY`     | JWT解析Key，可通过环境变量直接配置，如果没有配置则配置`OAUTH2_TOKEN_KEY_URL`，通过Rest API获取 | 否  |                                        |
| `OAUTH2_TOKEN_KEY_URL` | 获取JWT解析Key服务URL                                                   | 否  | http://127.0.0.1:6666/oauth2/token-key |
| `APP_ID`               | 获取JWT解析Key，数字签名校验App Id                                           | 否  |                                        |
| `APP_SECRET`           | 获取JWT解析Key，数字签名校验App Secret                                       | 否  |                                        |
| `AES_KEY`              | 获取JWT解析Key，AES Key用于解析返回加密Key                                     | 否  |                                        |
| `AES_IV`               | 获取JWT解析Key，AES Iv用于解析返回加密Key                                      | 否  |                                        |

#### 1.2 JWT token校验——远程服务校验token

### 环境变量配置

| 名称                       | 描述                                      | 必填 | 默认值                                      |
|--------------------------|-----------------------------------------|----|------------------------------------------
| `OAUTH2_CHECK_TOKEN_URL` | 校验token服务URL                            | 是  | http://127.0.0.1:6666/oauth2/check-token |
| `OAUTH2_CLIENT_ID`       | 校验token请求ClientId，用于生成Basic认证           | 是  |                                          |
| `OAUTH2_CLIENT_SECRET`   | 校验token请求ClientSecret，用于生成Basic认证       | 是  |                                          |
| `OAUTH2_RESP_CLAIMS_KEY` | 校验token返回结果，claims所在的路径（JSONPath），默认根路径 | 否  | /                                        |

### 1. k8s部署OAuth2代理认证服务OAuth2-Proxy

configmap配置文件部署文件如下：

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: oauth2-proxy-config
data:
  GIN_MODE: "release"
  SERVER_PORT: '6666'
  # OAuth2 token endpoint 如果在同一个集群则可配置集群内部通信地址（需修改）
  OAUTH2_ACCESS_TOKEN_ENDPOINT: "http://it-auth.dev-xyz-cloud.svc.cluster.local:21080/oauth2/token"
  # OAuth2 authorize endpoint （需修改）
  OAUTH2_AUTHORIZATION_ENDPOINT: "https://d-it-auth.gzv-k8s.xyz.com/oauth2/authorize"
  # 当前代理认证服务OAuth2-Proxy外网访问地址（需修改）
  OAUTH2_PROXY_ENDPOINT: "https://d-it-auth-proxy.gzv-k8s.xyz.com"
  # 授权认证成功之后转发地址参数（无需修改）
  OAUTH2_REDIRECT_URI_PARAM_NAME: "ru"
```

secret配置文件部署文件如下：

```yaml
kind: Secret
apiVersion: v1
metadata:
  name: oauth2-proxy-secret
stringData:
  # redis连接类型 single：单机模式，cluster：集群
  REDIS_TYPE: "cluster"
  # redis节点，如果是集群模式则host1:port1,host2:port2
  REDIS_NODES: "172.28.155.106:6379,172.28.232.136:6379,172.28.250.115:6379,172.28.51.152:6379,172.28.70.148:6379,172.28.98.8:6379"
  # redis登录账号
  REDIS_USER: ""
  # redis密码
  REDIS_PWD: "Y21WYVhNdGMzaFkycw"
  # 单机模式下redis数据库
  REDIS_DB: "3"
  # redis客户端名称，默认ingress-oauth2-proxy
  REDIS_CLI_NAME: "ingress-oauth2-proxy"
  # OAuth2 授权范围
  OAUTH2_SCOPE: "read"
  # OAuth2 客户端名称
  OAUTH2_CLIENT_ID: "lcx"
  # OAuth2 客户端密码
  OAUTH2_CLIENT_SECRET: "pi.s#t!xxx"
  # OAuth2 客户端对应的app id
  APP_ID: "f2aa0059a6e4456f8bac775c4fd***.xyz"
  # OAuth2 客户端对应的app secret
  APP_SECRET: "125809f6819ANBgkqpisshkiG***.xyz.***AASCAT4wggE6AgEAAkEAl3cpw0oz"
  # 当前app id 的aes key
  AES_KEY: "anFSRDdMejFralRVVExxyzJFWmx2MUI4"
  # 当前app id 的aes iv
  AES_IV: "MVNxZmlxWjExMxyz"
```

代理认证服务部署配置文件如下：

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: oauth2-proxy
  labels:
    app.xyz.com/instance: oauth2-proxy
    app.xyz.com/name: oauth2-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app.xyz.com/instance: oauth2-proxy
      app.xyz.com/name: oauth2-proxy
  template:
    metadata:
      labels:
        app.xyz.com/instance: oauth2-proxy
        app.xyz.com/name: oauth2-proxy
    spec:
      containers:
        - name: oauth2-proxy
          image: xyz.com/library/auth/oauth2-proxy:latest
          ports:
            - name: http-port
              containerPort: 6666
              protocol: TCP
          envFrom:
            - configMapRef:
                name: oauth2-proxy-config
            - secretRef:
                name: oauth2-proxy-secret
          resources: { }
          livenessProbe:
            tcpSocket:
              port: http-port
            initialDelaySeconds: 30
            timeoutSeconds: 5
            periodSeconds: 30
            successThreshold: 1
            failureThreshold: 5
          readinessProbe:
            tcpSocket:
              port: http-port
            initialDelaySeconds: 30
            timeoutSeconds: 5
            periodSeconds: 10
            successThreshold: 1
            failureThreshold: 5
          terminationMessagePath: /dev/termination-log
          terminationMessagePolicy: File
          imagePullPolicy: Always
      restartPolicy: Always
      terminationGracePeriodSeconds: 30
      dnsPolicy: ClusterFirst
      securityContext: { }
      schedulerName: default-scheduler
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%
      maxSurge: 25%
  revisionHistoryLimit: 10
  progressDeadlineSeconds: 600
```

--------------------------------

### 2. 配置认证ingress

配置示例如下：

```yaml
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: d-it-upms-demo
  annotations:
    # 代理认证服务登录地址 [代理认证服务地址]/login
    nginx.ingress.kubernetes.io/auth-signin: https://d-it-auth-proxy.gzv-k8s.xyz.com/login
    # 代理认证服务校验token地址 [代理认证服务地址]/check
    nginx.ingress.kubernetes.io/auth-url: http://oauth2-proxy.xyz-oauth2.svc.cluster.local:80/check
    # cookie跨域domain
    nginx.ingress.kubernetes.io/cors-allow-origin: https://*.xyz.com
    # 对代理认证服务返回缓存，认证成功时状态码为200 200 202 缓存30分钟
    nginx.ingress.kubernetes.io/auth-cache-duration: 200 201 202 30m
    nginx.ingress.kubernetes.io/auth-cache-key: $remote_user$http_authorization
    nginx.ingress.kubernetes.io/auth-keepalive-share-vars: 'true'
    nginx.ingress.kubernetes.io/auth-response-headers: Authorization,X-Auth-Request-User-Id,X-Auth-Request-User-Name
    nginx.ingress.kubernetes.io/auth-signin-redirect-param: ru
    nginx.ingress.kubernetes.io/cors-allow-credentials: 'true'
    nginx.ingress.kubernetes.io/enable-cors: 'true'
    nginx.ingress.kubernetes.io/enable-global-auth: 'true'
spec:
  ingressClassName: nginx-ing
  tls:
    - hosts:
        - d-it-upms-proxy-11.gzv-k8s.xyz.com
      secretName: gzv-k8s
  rules:
    - host: d-it-upms-proxy-11.gzv-k8s.xyz.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: it-upms
                port:
                  number: 21080
```

```yaml
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: d-it-kibana-demo
  annotations:
    # 代理认证服务登录地址 [代理认证服务地址]/login
    nginx.ingress.kubernetes.io/auth-signin: https://d-it-auth-proxy.gzv-k8s.xyz.com/login
    # 代理认证服务校验token地址 [代理认证服务地址]/check
    nginx.ingress.kubernetes.io/auth-url: http://oauth2-proxy.xyz-oauth2.svc.cluster.local:80/check
    # cookie跨域domain
    nginx.ingress.kubernetes.io/cors-allow-origin: https://*.xyz.com
    # 对代理认证服务返回缓存，认证成功时状态码为200 200 202 缓存30分钟
    nginx.ingress.kubernetes.io/auth-cache-duration: 200 201 202 30m
    nginx.ingress.kubernetes.io/auth-cache-key: $remote_user$http_authorization
    nginx.ingress.kubernetes.io/auth-keepalive-share-vars: 'true'
    nginx.ingress.kubernetes.io/auth-response-headers: Authorization,X-Auth-Request-User-Id,X-Auth-Request-User-Name
    nginx.ingress.kubernetes.io/auth-signin-redirect-param: ru
    nginx.ingress.kubernetes.io/cors-allow-credentials: 'true'
    nginx.ingress.kubernetes.io/enable-cors: 'true'
    nginx.ingress.kubernetes.io/enable-global-auth: 'true'
spec:
  ingressClassName: nginx-ing
  tls:
    - hosts:
        - kiba-oauth2-proxy.gzv-k8s.xyz.com
      secretName: gzv-k8s
  rules:
    - host: kiba-oauth2-proxy.gzv-k8s.xyz.com.gzv-k8s.xyz.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: kibana-kibana
                port:
                  number: 5601
```


