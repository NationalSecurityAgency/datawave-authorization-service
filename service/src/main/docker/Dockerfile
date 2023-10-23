FROM azul/zulu-openjdk-alpine:11

LABEL version=${project.version} \
      run="docker run ${docker.image.prefix}${project.artifactId}:latest" \
      description="${project.description}"

ADD ${project.build.finalName}-exec.jar /app.jar
RUN mkdir -p  /var/run/secrets/kubernetes.io/serviceaccount/ && \
    touch  /var/run/secrets/kubernetes.io/serviceaccount/token && \
    touch /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
RUN apk add libc6-compat curl

EXPOSE 8443 8080
ENTRYPOINT ["java","-jar","app.jar"]