FROM golang:latest as go-builder
MAINTAINER Valentin Kuznetsov vkuznet@gmail.com

# build procedure
ENV PROJECT=Authz
ENV WDIR=/data
WORKDIR $WDIR
RUN mkdir /build
RUN git clone https://github.com/CHESSComputing/$PROJECT
RUN cd $PROJECT && CGO_ENABLED=1 make && cp srv /build

# build final image for given image
# FROM alpine as final
# FROM gcr.io/distroless/static as final
# for gibc library we will use debian:stretch
FROM debian:stable-slim
RUN mkdir -p /data
COPY --from=go-builder /build/srv /data
RUN ls -al /data
RUN ldd /data/srv
LABEL org.opencontainers.image.description="FOXDEN Authz service"
LABEL org.opencontainers.image.source=https://github.com/chesscomputing/frontend
LABEL org.opencontainers.image.licenses=MIT
ENTRYPOINT: ['/data/srv']
