FROM golang:1.20.5-bullseye as build

WORKDIR /app

RUN go install github.com/cosmtrek/air@latest

COPY go.* ./
COPY api/go.* ./api/
COPY vault/go.* ./vault/
COPY logger/go.* ./logger/

RUN go mod download

COPY . ./

RUN cd vault && go build && cd ..
RUN cd api && go build && cd ..


## Simulator
FROM python:3.11 as simulator

COPY simulator/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY simulator/ ./


## Deploy
FROM gcr.io/distroless/base-debian11 as deploy

WORKDIR /
COPY --from=build /app/api/api .
COPY --from=build /app/conf/dev.conf.toml ./conf.toml

EXPOSE 3000

USER nonroot:nonroot
