FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY shop ./shop
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /tenantshop .

FROM scratch
COPY --from=build /tenantshop /tenantshop
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/tenantshop"]
