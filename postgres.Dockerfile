FROM postgres:13

ENV POSTGRES_USER=admin
ENV POSTGRES_PASSWORD=testing321
ENV POSTGRES_DB=trustpoint_db

EXPOSE 5432
