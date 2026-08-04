FROM golang:1.25-bookworm AS app

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build -gcflags="all=-N -l" -o ./main main.go && chmod +x ./main

ENTRYPOINT [ "./main" ]

# This is a debug image that runs the app in the container with dlv instead of the default entrypoint.
# This is useful for debugging the app in the container.
# To use the debug build, update the `target` for the `app` service in the `docker-compose.yml` file to `debug`.
FROM app AS debug
ENV GOTOOLCHAIN=auto

ENTRYPOINT ["go", "tool", "dlv", "debug", "--headless", "--listen=:40000", "--accept-multiclient", "--api-version=2", "--log", "--log-output=debugger,gdbwire,lldbout,debuglineerr,rpc,dap,fncall,minidump,stack", "/app/main.go", "--"]