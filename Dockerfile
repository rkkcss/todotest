FROM ubuntu:latest AS build
RUN apt-get update && apt-get install -y maven
WORKDIR /app
COPY . .
RUN mvn package -DskipTests

FROM openjdk:17-jdk-slim
EXPOSE 8080
WORKDIR /app
COPY --from=build /app/target/*.jar /app/app.jar

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
