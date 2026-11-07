# syntax=docker/dockerfile:1
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/ratchetd ./cmd/ratchetd
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/ratchet-k8s-webhook ./cmd/ratchet-k8s-webhook

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/ratchetd"]
