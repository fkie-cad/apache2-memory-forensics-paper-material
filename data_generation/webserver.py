import time
import docker
from requests.auth import HTTPBasicAuth

from docker_env import DockerEnv
import requests


class Server:
    env = None
    base_image = None
    stop_container = True
    container_name = None
    ports = None

    def __init__(self, image=None, uploads=None, commands=None):
        if image:
            try:
                with DockerEnv(image=image) as env:
                    self.env = env
                    self.base_image = self.env.container.image
                    print('Image found: ', self.base_image)
            except docker.errors.ImageNotFound as e:
                print('Image not found, creating image ...')
                self.get_base_image(image=image, uploads=uploads, commands=commands)
                print('Image created:', self.base_image)
        else:
            print('No image given, creating image ...')
            self.get_base_image(image='base-image', uploads=uploads, commands=commands)
            print('Image created:', self.base_image, uploads)

    def get_base_image(self, image, uploads, commands):
        raise NotImplementedError('must be implemented by webserver class')

    def __enter__(self):
        self.env = DockerEnv(image=self.base_image,
                             container_name=self.container_name,
                             stop_container=self.stop_container,
                             ports=self.ports).__enter__()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.env.__exit__(exc_type, exc_value, exc_traceback)

    def upload(self, src_path, dest_path):
        self.env.upload_files(src_path, dest_path)

    def download(self, src_path, dest_path):
        self.env.download_files(src_path, dest_path)

    def delete(self, path):
        self.env.delete(path)

    def execute(self, commands):
        for cmd in commands:
            self.env.execute_command(cmd)

    def request(self, url, verify=True, username=None, password=None):
        auth = None
        if username and password:
            auth = HTTPBasicAuth(username=username, password=password)
        requests.get(url, verify=verify, stream=True, auth=auth)

    def start_network_capture(self, name):
        self.env.execute_command(f'tcpdump -U -s 65535 -w {name}', detach=True)

    def stop_network_capture(self):
        time.sleep(2)
        self.env.execute_command('pkill -2 tcpdump')

    def start_proxied_server(self, port, directory):
        self.env.execute_command(['sh', '-c', f'python3.9 -m http.server {port} '
                                              f'--directory {directory} '
                                              f'--bind 127.0.0.1 | tee -a /tmp/proxied.log'],
                                 detach=True)
