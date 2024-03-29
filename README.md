<h1 align="center">Agent Metasploit</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Metasploit is a powerful penetration testing framework._

---

This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for the [Metasploit Framework](https://github.com/rapid7/metasploit-framework) by Rapid7.

## Getting Started
To perform your first scan, simply run the following command:
```shell
oxo scan run --install --agent agent/ostorlab/metasploit ip 8.8.8.8
``` 

This command will download and install `agent/ostorlab/metasploit` and target the ip `8.8.8.8`.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent Metasploit can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/metasploit
 ```

You can then run the agent with the following command:
```shell
oxo scan run --agent agent/ostorlab/metasploit ip 8.8.8.8
```


### Build directly from the repository

 1. To build the metasploit agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_metasploit.git && cd agent_metasploit
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    oxo scan run --agent agent//metasploit ip 8.8.8.8
    ```
	 * If you specified an organization when building the image:
    ```shell
    oxo scan run --agent agent/[ORGANIZATION]/metasploit ip 8.8.8.8
    ```

### Run agent metasploit with module options

- Payload: `auxiliary/scanner/portscan/tcp`
- Options:
  - PORTS: `80, 443`

Example `agent_group.yaml` file to trigger the scan:

```yaml
kind: AgentGroup
description: Metasploit.
agents:
  - key: agent//metasploit
    args:
      - name: config
        type: array
        value: 
          - module: 'auxiliary/scanner/portscan/tcp'
            options:
              - name: "PORTS"
                value: "80,443"
          - module: 'auxiliary/scanner/http/enum_wayback'
            options:
              - name: "DOMAIN"
                value: "www.ostorlab.co"
```

`oxo scan run -g agent_group.yaml domain-name www.ostorlab.co`

## License
[Apache](./LICENSE)
