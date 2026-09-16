# syntax=docker/dockerfile:1.7
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /occludra-gateway .

FROM alpine:3.20
RUN adduser -D -u 10003 occludra && apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*
COPY --from=build /occludra-gateway /usr/local/bin/occludra-gateway
USER 10003:10003
ENV OCCLUDRA_LISTEN=0.0.0.0:8080 \
    OCCLUDRA_POLICY_FILE=/conf/policy.yaml
EXPOSE 8080
ENTRYPOINT ["occludra-gateway"]
