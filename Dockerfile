FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get install -y python3 \
                                         python3-pip \
                                         metasploit-framework
COPY requirement.txt /requirement.txt
RUN python3 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/metasploit_agent.py"]