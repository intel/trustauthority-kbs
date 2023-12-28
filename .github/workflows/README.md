# CI Workflows

## Build
To build docker images

## Tests
To run all unit tests

## Push
To push docker images to registry

## Checkmarx scan
Static code analysis tool

### Checkmarx Setup instructions for runners

Build and push image to private registry

Build Docker image with following Dockerfile and psuh it to private registry
```shell
FROM docker.io/checkmarx/cx-flow

COPY Root.crt /app/

RUN keytool -import -trustcacerts -keystore /etc/ssl/certs/java/cacerts -storepass changeit -noprompt -alias IntelCertIntelCA5A-1-base64.crt -file "Root.crt"
```

Root.crt needs to be requested from IT to connect to checkmarx server.

