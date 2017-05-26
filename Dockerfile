FROM alpine:3.6

MAINTAINER mozhuli <weidonglee27@gmail.com>

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# Add source files.
ADD *.go /go/src/github.com/mozhuli/kube-qos/
ADD pkg /go/src/github.com/mozhuli/kube-qos/pkg
ADD vendor /go/src/github.com/mozhuli/kube-qos/vendor


RUN set -ex \
	&& apk update && apk add --no-cache --virtual .build-deps \
		bash \
		musl-dev \
		openssl \
		go \
		ca-certificates \
    && cd /go/src/github.com/mozhuli/kube-qos \
    && go build -v -i -o /bin/kube-qos  kube-qos.go \
	&& rm -rf /go \
	&& apk del .build-deps

CMD ["kube-qos"]