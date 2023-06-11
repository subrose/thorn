FROM golang:1.20.2-bullseye as build

WORKDIR /app

COPY . ./
RUN go mod download

RUN cd vault && go build && cd ..
RUN cd api && go build && cd ..

## Deploy
FROM gcr.io/distroless/base-debian11 as deploy

WORKDIR /
COPY --from=build /app/api/api .
COPY --from=build /app/conf/dev.conf.toml ./conf.toml

EXPOSE 3000

USER nonroot:nonroot
