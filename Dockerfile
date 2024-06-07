
# Get the builder image
FROM maven:3.9.7-eclipse-temurin-17 AS builder
COPY . /build
WORKDIR /build
# Build the app
# Artifact will be stored at /build/target/json-web-key-generator-jar-with-dependencies.jar
RUN mvn package

# Build the image with the new .jar binary
# We need a jre 11+ starter container for this
FROM eclipse-temurin:17-jre-focal
ARG GIT_COMMIT=unspecified
ARG GIT_TAG=unspecified
LABEL org.opencontainers.image.authors="Besmir Zanaj"
LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.version="$GIT_TAG"
COPY --from=0 /build/target/json-web-key-generator-jar-with-dependencies.jar ./json-web-key-generator.jar
ENTRYPOINT ["java", "-jar", "json-web-key-generator.jar"]
