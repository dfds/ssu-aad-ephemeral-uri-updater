FROM golang:1.22-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

COPY azure /app/azure
COPY model /app/model
COPY cmds/main.go /app/cmds/main.go
COPY conf /app/conf
COPY static /app/static
COPY util /app/util

RUN go install github.com/GeertJohan/go.rice/rice@latest && cd model/static && rice embed-go && cd ../..
RUN go build -o /app/app /app/cmds/main.go

FROM golang:1.22-alpine

COPY --from=build /app/app /app/app

CMD [ "/app/app" ]