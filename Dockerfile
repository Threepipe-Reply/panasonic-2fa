FROM python:3.9

ENV DBUSER = root
ENV DBPASSWORD = 32gjh11vq3u4UKTC73RUGsSDf

EXPOSE 5000/tcp

WORKDIR /app

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . .