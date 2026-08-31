# Imagen reproducible de malpipe.
# El análisis dinámico se delega a un sandbox gestionado (tria.ge) vía API,
# así que este contenedor NO detona muestras: solo hace estático y orquesta.

FROM python:3.12-slim

# libmagic/libfuzzy opcionales; se instalan solo si activas ssdeep.
# RUN apt-get update && apt-get install -y --no-install-recommends libfuzzy2 \
#     && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir ".[web]"

# Usuario sin privilegios
RUN useradd -m analyst
USER analyst

# Muestras entran por /samples, informes salen por /reports (monta volúmenes)
ENTRYPOINT ["malpipe"]
CMD ["--help"]
