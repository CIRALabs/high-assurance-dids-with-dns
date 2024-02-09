FROM python:3.10
# RUN apk update && apk add postgresql-dev gcc python3-dev musl-dev
# RUN pip3 install psycopg2-binary

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY . .

# CMD [ "uvicorn","app.main:app", "--host","0.0.0.0","--port","80"] 

CMD ["gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:80"]