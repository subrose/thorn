FROM golang:1.21-bullseye as dev

WORKDIR /app
RUN go install github.com/cosmtrek/air@latest
COPY . .
RUN go mod download

FROM golang:1.21-bullseye as build

WORKDIR /app
RUN go install github.com/cosmtrek/air@latest
COPY . .
RUN go mod download
RUN go build -o /go/bin/api ./api 

## Simulator
FROM python:3.11 as simulator

COPY simulator/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y redis-tools
COPY simulator/ ./

## Deploy
FROM gcr.io/distroless/base-debian11 as deploy

WORKDIR /
COPY --from=build /go/bin/api ./api
COPY --from=build /app/conf/dev.conf.toml ./conf.toml 
EXPOSE 3001
USER nonroot:nonroot
