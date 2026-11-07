FROM python:3.13-slim
WORKDIR /fixture
COPY server.py /fixture/server.py
USER 65534:65534
EXPOSE 8001/tcp 9001/udp
CMD ["python", "/fixture/server.py"]
