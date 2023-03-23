FROM python:3.9-buster

WORKDIR  /usr/scr/flask_app
COPY requirements.txt .
RUN pip install --ignore-installed --no-cache-dir -r  requirements.txt
COPY . .
