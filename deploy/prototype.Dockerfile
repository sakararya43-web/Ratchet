FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/ ./cmd/ratchetd ./cmd/ratchet-sim ./cmd/ratchet-connector ./cmd/ratchet-prototype ./cmd/ratchet-authority

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /usr/local/bin/
COPY policies/ /app/policies/
RUN mkdir -p /data/core /data/edge /data/operator /data/simulator && chown -R 65532:65532 /data
USER 65532:65532
WORKDIR /app
CMD ["ratchet-prototype", "health"]

FROM postgres:17@sha256:3b0cda93be7c8dba2ed484d19393d93845dc3dafb88973e248ba8e6d99d784e1 AS database
COPY deploy/compose/postgres-init.sh /docker-entrypoint-initdb.d/10-ratchet.sh
RUN chmod 755 /docker-entrypoint-initdb.d/10-ratchet.sh
