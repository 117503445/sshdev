FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-s -w" -o sshdev ./cmd/sshdev

FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN addgroup -g 65532 nonroot &&\
    adduser -S -u 65532 -G nonroot nonroot
USER nonroot:nonroot

WORKDIR /

COPY --from=builder /app/sshdev .

EXPOSE 2222

ENTRYPOINT ["./sshdev"]
CMD ["run"]