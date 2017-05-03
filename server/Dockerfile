FROM golang
MAINTAINER Max Harley <maxh@maxh.io>

RUN go get -u github.com/labstack/echo
RUN go get -u github.com/t94j0/CTFNmapScanner

RUN go install github.com/t94j0/CTFNmapScanner/server

ENTRYPOINT /go/bin/server

EXPOSE 8080
