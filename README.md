<h1 align="center">Agent Metasploit</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_metasploit">
<img src="https://img.shields.io/github/stars/ostorlab/agent_metasploit">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Metasploit is a powerful penetration testing framework._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_metasploit/blob/main/images/logo.png" alt="agent-metasploit" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for the [Metasploit Framework](https://github.com/rapid7/metasploit-framework) by Rapid7.

## Getting Started
To perform your first scan, simply run the following command:
```shell
ostorlab scan run --install --agent agent/ostorlab/metasploit ip 8.8.8.8
```

This command will download and install `agent/ostorlab/metasploit` and target the ip `8.8.8.8`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent Metasploit can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/metasploit
 ```

You can then run the agent with the following command:
```shell
ostorlab scan run --agent agent/ostorlab/metasploit ip 8.8.8.8
```


### Build directly from the repository

 1. To build the metasploit agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_metasploit.git && cd agent_metasploit
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostorlab agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    ostorlab scan run --agent agent//metasploit ip 8.8.8.8
    ```
	 * If you specified an organization when building the image:
    ```shell
    ostorlab scan run --agent agent/[ORGANIZATION]/metasploit ip 8.8.8.8
    ```


## License
[Apache](./LICENSE)
