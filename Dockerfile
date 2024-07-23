FROM golang:1.18 AS build

WORKDIR /usr/src/mlflow-oidc-proxy

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY pkg ./pkg
RUN GCO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -extldflags "-static"" -tags netgo main.go

FROM alpine:3.16 AS certs

RUN apk add ca-certificates-bundle

FROM scratch

COPY --from=build /usr/src/mlflow-oidc-proxy/main /proxy
COPY --from=certs /etc/ssl/cert.pem /etc/ssl/cert.pem

VOLUME /etc/mlflow-oidc-proxy

ENTRYPOINT ["/proxy"]
CMD ["--config", "/etc/mlflow-oidc-proxy/mlflow-oidc-proxy.cfg"]
