FROM python:3.9-alpine
COPY . /classwork-pp-flask
WORKDIR /classwork-pp-flask

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
EXPOSE 5000

ENV FLASK_APP=app/__init__.py 
ENV FLASK_RUN_HOST=0.0.0.0
#ENTRYPOINT ["python3"]
CMD ["sh","run.sh"]