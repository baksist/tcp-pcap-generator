FROM imachug/kyzylborda_lib
RUN pip install dpkt
RUN mkdir /app
ENTRYPOINT ["/app/main.py"]