FROM python:latest
WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt
COPY src/*.py /app/
COPY main.py /app/
CMD [ "python main.py --server" ]

