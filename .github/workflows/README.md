# CI Workflows

## Build
To build docker images

## Tests
To run all unit tests

## Push
To push docker images to registry

## Snyk scan
To scan code dependencies for vulnerabities.

### Snyk Setup instructions for runners

1. Install brew
```shell
sudo apt-get install build-essential
sudo apt install git -y
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
```

2. Install snyk
```shell
brew tap snyk/tap
brew install snyk
```

3. Add snyk to PATH
```shell
sudo cp /home/linuxbrew/.linuxbrew/bin/snyk /usr/bin/
```

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

