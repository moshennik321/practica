# ---- build stage ----
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

COPY . .
RUN chmod +x ./mvnw && ./mvnw -DskipTests package

# ---- runtime stage ----
FROM eclipse-temurin:21-jre
WORKDIR /app

# Create non-root user/group
RUN groupadd -r app && useradd -r -g app app

# Copy jar and set permissions
COPY --from=build /app/target/*.jar /app/app.jar
RUN chown -R app:app /app

# Run as non-root
USER app

EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]