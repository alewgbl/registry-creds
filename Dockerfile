FROM gcr.io/distroless/base
COPY registry-creds registry-creds
ENTRYPOINT ["/registry-creds"]
