FROM    golang as builder
RUN     mkdir /go/both
COPY    main.go /go/both/both.go
RUN     cd /go/both && go mod init both && go mod tidy && GOOS=linux GOARCH=386 CGO_ENABLED=0 go build

FROM    scratch
COPY    --from=builder /go/both/both /both

EXPOSE  8080
CMD     [ "-http", "127.0.0.1:80", "-https", "127.0.0.1:443" ]
ENTRYPOINT [ "/both" ]