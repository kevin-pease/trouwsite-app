FROM python:3.9-buster

WORKDIR  /usr/scr/flask_app
COPY . .
COPY credentials.txt .
RUN apt-get update
RUN apt-get -y install python3-pip
RUN python -m pip install --upgrade pip
RUN pip install --ignore-installed --no-cache-dir -r  requirements.txt


