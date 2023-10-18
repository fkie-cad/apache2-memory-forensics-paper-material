# How to Create Test Data Using the Framework

## Prerequisites

For the framework to work you have to have Docker installed. Follow the installation instructions provided by the Docker website: (https://www.docker.com/get-started/)

You also have to install PyYAML and Docker SDK for Python using pip. (https://pypi.org/project/PyYAML/, https://pypi.org/project/docker/)
```
pip3 install PyYAML
pip3 install docker
``` 

## Events

To create data you can use "Events". These events describe different scearions which can occur while running a webserver. You can find a list of events in the directory `./data_generation/apache_events/`.
Each of these events has a dedicated `event-n.yaml` file. You can modify the YAML-file with different "actions" to your needs. Example actions would include 
```
execute
start_network_capture
request
upload
```
In total there are 8 predefined events which can be used to generate data. 


## Start Creating Data

After choosing the event you can now run e.g. 
`python3 framework.py apache_events/event-5-https/event-5.yaml`
to create data.
