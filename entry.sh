#!/bin/bash

supervisord -c /etc/supervisor/conf.d/supervisord.conf
python3 /app/agent/metasploit_agent.py