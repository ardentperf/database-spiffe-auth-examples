FROM golang:1.25-bookworm AS app

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build -o ./main main.go && chmod +x ./main

ENTRYPOINT [ "./main" ]
