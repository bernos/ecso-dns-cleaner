FROM golang:1.8-alpine

RUN mkdir -p /go/src/app
WORKDIR /go/src/app

CMD ["go-wrapper", "run"]

COPY . /go/src/app

RUN apk update && apk upgrade && apk add --no-cache git

RUN go-wrapper download
RUN go-wrapper install
