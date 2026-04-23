#!/bin/bash

supervisord -c /etc/supervisor/conf.d/supervisord.conf
python3.14 /app/agent/metasploit_agent.py