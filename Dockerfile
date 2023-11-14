FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get install -y python3.11 \
                                         python3-pip \
                                         metasploit-framework \
                                         procps \
                                         supervisor
COPY requirement.txt /requirement.txt
RUN python3 -m pip install -r /requirement.txt
COPY tools /tools
RUN pip install -e /tools/pymetasploit3
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY entry.sh /app/entry.sh
COPY ostorlab.yaml /app/agent/ostorlab.yaml
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
WORKDIR /app
CMD ["bash", "entry.sh"]