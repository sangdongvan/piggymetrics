FROM openjdk:8-alpine
MAINTAINER Alexander Lukyanchikov <sqshq@sqshq.com>

ENTRYPOINT ["/usr/bin/java", "-jar", "/code/app.jar"]

# Add app itself
ARG JAR_FILE
ADD target/${JAR_FILE} /code/app.jar
