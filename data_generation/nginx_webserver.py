from webserver import Server, DockerEnv
import time
from pathlib import Path


class NginxServer(Server):

    def __init__(self, image=None, uploads=None, commands=None):
        super().__init__(image, uploads, commands)

    def get_base_image(self, image, uploads, commands):
        with DockerEnv(Path('Dockerfile'), from_image=False, delete_image=True) as env:
            self.env = env
            print('installing nginx ...')
            self.env.execute_command('apt update')
            self.env.execute_command('apt install nginx -y')
            self.env.execute_command('apt install apache2-utils -y')
            self.env.execute_command('mkdir -p /etc/apache2/')
            self.env.execute_command('touch /etc/apache2/.htpasswd')
            time.sleep(1)
            for key, value in uploads.items():
                self.upload(key, value)
            self.execute(commands)
            self.base_image = self.env.container.commit(repository=image)

    def start(self):
        self.env.execute_command('nginx', environment={'LD_PRELOAD': '/libsslkeylog.so'})
        time.sleep(1)

    def reload(self):
        self.env.execute_command('nginx -s reload')

    def create_user(self, username, password):
        self.env.execute_command(f'htpasswd -b /etc/apache2/.htpasswd {username} {password}')
