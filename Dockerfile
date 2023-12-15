FROM golang:1.21.4-bookworm as base

WORKDIR /app
RUN go install github.com/cosmtrek/air@latest

COPY go.* .
COPY api/go.* ./api/
COPY vault/go.* ./vault/
COPY logger/go.* ./logger/
RUN go mod download

COPY . .
RUN go build -o /go/bin/api ./api 

## Simulator
FROM python:3.11 as simulator

COPY simulator/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY simulator/ ./

## Deploy
FROM gcr.io/distroless/base-debian12 as deploy

WORKDIR /
COPY --from=build /go/bin/api ./api
EXPOSE 3001
USER nonroot:nonroot
