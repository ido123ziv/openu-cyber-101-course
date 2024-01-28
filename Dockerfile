FROM python:latest
WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt
COPY old-deprecated/main.py /app/
CMD [ "python main.py" ]

