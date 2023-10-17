import os
import sys
import yaml
import docker
from pathlib import Path
from yaml import SafeLoader
from nginx_webserver import NginxServer
from apache_webserver import ApacheServer


class Framework:

    def __init__(self, path_to_yaml):
        with open(path_to_yaml, 'r') as yaml_stream:
            data_gen_yaml = yaml.load(yaml_stream, Loader=SafeLoader)
        prev_cwd = Path.cwd()
        os.chdir(Path(path_to_yaml).parent)
        data_gen_yaml.update(yaml.load(open(data_gen_yaml['include']), Loader=SafeLoader))
        os.chdir(prev_cwd)

        server_type = data_gen_yaml['server']
        base_image = data_gen_yaml['base-image']

        if server_type == 'Nginx':
            self.server = NginxServer(image=base_image['image-name'],
                                      uploads=data_gen_yaml['uploads'],
                                      commands=data_gen_yaml['execute'])
        elif server_type == 'Apache':
            self.server = ApacheServer(image=base_image['image-name'],
                                       uploads=data_gen_yaml['uploads'],
                                       commands=data_gen_yaml['execute'])

        for key, value in data_gen_yaml.items():
            if 'event' in key:
                self.execute_event(value)

        if not base_image.get('keep-image', False):
            try:
                self.server.env.client.images.remove(
                    self.server.env.container.image.attrs['RepoTags'][0]
                )
            except docker.errors.APIError as e:
                print('Can not remove the base image, because container(s) still running')

    def execute_event(self, event):
        if not event.get('execute', True):
            return

        if 'container' in event:
            event_container = event['container']
            self.server.stop_container = (not event_container.get('keep-container-running', False))
            self.server.container_name = event_container.get('container-name', None)
            self.server.ports = event_container.get('ports', None)
        else:
            self.server.stop_container = True
            self.server.container_name = None
            self.server.ports = None

        with self.server as cont:
            print('Executing actions ...')
            for action in event['actions']:
                print(f'{action}')
                if type(action) is str:
                    method = getattr(cont, action)
                    method()
                elif type(action) is dict:
                    method_str = next(iter(action))
                    event_method = getattr(cont, method_str)
                    if method_str == 'download' or method_str == 'upload':
                        for key, value in action[method_str].items():
                            event_method(key, value)
                    elif method_str == 'execute':
                        command_list = action[method_str]
                        event_method(command_list)
                    else:
                        method_attributes = action[method_str]
                        event_method(**method_attributes)

            if 'image' in event:
                event_image = event['image']
                if event_image.get('snapshot', False):
                    self.server.env.container.commit(repository=event_image.get('image-name', None))


def main(argv):
    Framework(argv[0])


if __name__ == '__main__':
    main(sys.argv[1:])
