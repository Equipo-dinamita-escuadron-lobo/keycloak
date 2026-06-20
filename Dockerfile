# Etapa 1: Build con dependencias cacheables
FROM eclipse-temurin:17-jdk-alpine AS builder

# 1. Directorio de trabajo
WORKDIR /app

# 2. Copiar archivos necesarios para cachear dependencias
COPY .mvn .mvn
COPY mvnw pom.xml ./

# 3. Preparar el entorno (dos2unix para compatibilidad)
RUN apk add --no-cache dos2unix && \
    dos2unix ./mvnw && \
    chmod +x ./mvnw

# 4. Descarga de dependencias para cacheo (sin compilar)
RUN ./mvnw dependency:go-offline

# 5. Copiar el código fuente (esto invalida el cache solo si cambia src/)
COPY src ./src

# 6. Compilar y empaquetar (sin ejecutar tests para velocidad)
RUN ./mvnw clean package -DskipTests

# Etapa 2: Imagen final liviana para producción
FROM eclipse-temurin:17-jre-alpine AS main

# 7. Directorio de trabajo
WORKDIR /app

# 8. Copiar solo el artefacto necesario desde la etapa anterior
COPY --from=builder /app/target/*.jar /usr/local/springboot-app.jar

# 9. Exponer el puerto usado por Spring Boot (por defecto)
EXPOSE 8080

# 10. Comando de arranque
CMD ["java", "-jar", "/usr/local/springboot-app.jar"]
