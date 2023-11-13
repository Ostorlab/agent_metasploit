FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get install -y python3.11 \
                                         python3-pip \
                                         metasploit-framework \
                                         procps
COPY requirement.txt /requirement.txt
RUN python3 -m pip install -r /requirement.txt
COPY tools /tools
RUN pip install -e /tools/pymetasploit3
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
RUN msfrpcd -P ostorlab123 -p 55555
CMD ["python3", "/app/agent/metasploit_agent.py"]