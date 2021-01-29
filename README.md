# scap-v2-prototype
The SCAP v2 Prototype implements the components and basic message flows for the SCAP v2 Architecture which is defined [here](https://groups.google.com/a/list.nist.gov/group/scap-dev-endpoint/attach/875891ab9f4df/SCAP%20v2%20Data%20Collection%20Architecture%2020200818.docx?part=0.1).

## Build Instructions
The following provides instructions on how to set up the SCAP v2 Prototype on Ubuntu 20.04.

### Install Docker
Docker can be installed using the instructions found [here](https://docs.docker.com/engine/install/ubuntu/). Docker may be installed on other operating systems by following the instructions found [here](https://docs.docker.com/get-docker/).

### Install OpenDXL
The [OpenDXL Broker](https://hub.docker.com/r/opendxl/opendxl-broker/) Docker image can be retrieved using the following command.

`sudo docker pull opendxl/opendxl-broker`

Next, prepare the directory structure for the OpenDXL Broker. Assuming you are in a user home directory (e.g., /home/dhaynes), run the following commands. These commands are based on the instructions found [here](https://github.com/opendxl/opendxl-broker/wiki/Command-Line-OpenDXL-Broker-Installation).

`mkdir opendxl`<br>
`mkdir opendxl/opendxl-broker`

Next, run OpenDXL with the following command. The -v argument should point to the directory structure created in the previous step. 

`sudo docker run -d --name opendxl-broker -p 8443:8443 -p 8883:8883 -v /home/dhaynes/opendxl/opendxl-broker:/dxlbroker-volume opendxl/opendxl-broker`

Check to see that the OpenDXL Docker image is running using the following command.

`sudo docker ps`

If there are no directories (config, keystore, logs, policy) in opendxl-broker, ensure that docker has permission to create them and re-run OpenDXL as above.

`sudo chmod g+w opendxl/opendxl-broker`  
`sudo chgrp ubuntu opendxl/opendxl-broker`   Grant write permission to group that sudo runs in (`ubuntu`)

### Install OpenDXL Client Library
The following was based on the instructions found [here](https://opendxl.github.io/opendxl-client-python/pydoc/installation.html).

First, check the OpenSSL version used by Python.

`python3`

Then, type the following.

`>>> import ssl`<br>
`>>> ssl.OPENSSL_VERSION`

Once the OpenSSL version is verified (1.0.1 or greater), type the following.

`>>> quit()`

Next, install pip.

`sudo apt install python3-pip`

Then, the OpenDXL client library can be installed using the following command.

`pip3 install dxlclient`

Once installed, provision the OpenDXL client by running the following command. This will create files needed by the OpenDXL client to connect to the OpenDXL broker in the /home/dhaynes/opendxl/opendxl-client directory. You will have to enter the OpenDXL broker username (admin) and password (password).

`python3 -m dxlclient provisionconfig /home/dhaynes/opendxl/opendxl-client 127.0.0.1 opendxl-client`

### Get the SCAP v2 Prototype
Retrieve the SCAP v2 Prototype by running the following command. 

`git clone https://github.com/opencybersecurityalliance/scap-v2-prototype.git`

Create environment variable pointing to the OpenDXL client configuration file created during provisioning.

`export CONFIG="/home/dhaynes/opendxl/opendxl-client/dxlclient.config"`

Now, the individual components of the SCAP v2 Architecture can be started from the scap-v2-prototype/src directory.

Start the Manager.

`python3 manager.py`

Start the Repository. The repository must be started before any Collector, PCX, or PCE.

`python3 repository.py`

Start the Collector. The Collector must be started before any PCX or PCE that reports to it.

`python3 collector.py <collector_config in /config>`

Start the PCX. The PCX must be started before any PCE that reports to it.

`python3 pcx.py <pcx_config in /config>`

Start the PCE. 

`python3 pce.py <pce_config in /config>`

Start the Application.

`python3 application.py <application_config in /config>`

## Getting Help
To get help with the SCAP v2 Prototype or to report an issue. Please open an [issue](https://github.com/opencybersecurityalliance/scap-v2-prototype/issues) or send an email to https://groups.google.com/a/list.nist.gov/g/scap-dev-endpoint.
