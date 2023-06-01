FROM    golang as builder
RUN     mkdir /go/basicweb
COPY    basicweb.go /go/basicweb/basicweb.go
RUN     cd /go/basicweb && go mod init basicweb && go mod tidy && GOOS=linux GOARCH=386 CGO_ENABLED=0 go build

FROM    scratch
COPY    --from=builder /go/basicweb/basicweb /basicweb

EXPOSE  80
ENTRYPOINT [ "/basicweb", "-echo" ]