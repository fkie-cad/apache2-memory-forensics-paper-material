from webserver import Server, DockerEnv
import time
from pathlib import Path


class ApacheServer(Server):

    def __init__(self, image=None, uploads=None, commands=None):
        super().__init__(image, uploads, commands)

    def get_base_image(self, image, uploads, commands):
        with DockerEnv(Path('Dockerfile'), from_image=False, delete_image=True) as env:
            self.env = env
            print('installing apache ...')
            self.env.execute_command('apt update')
            self.env.execute_command('apt install systemctl -y')
            self.env.execute_command('apt install apache2 -y')
            self.env.execute_command('apt install apache2-utils -y')
            self.env.execute_command('touch /tmp/premaster.txt')
            self.env.execute_command('chmod -R 777 /tmp/premaster.txt')
            self.env.execute_command('mkdir -p /etc/systemd/system/apache2.service.d')
            self.env.execute_command('touch /etc/systemd/system/apache2.service.d/override.conf')
            with open('/tmp/override.conf', 'w+') as preload_conf:
                preload_conf.write('[Service]\n'
                                   'Environment=LD_PRELOAD=/libsslkeylog.so\n'
                                   'Environment=SSLKEYLOGFILE=/tmp/premaster.txt\n')
            self.upload("/tmp/override.conf", "/etc/systemd/system/apache2.service.d/override.conf")
            if Path('/tmp/override.conf').exists():
                Path('/tmp/override.conf').resolve()
            time.sleep(1)
            for key, value in uploads.items():
                self.upload(key, value)
            self.execute(commands)
            self.env.execute_command('systemctl reload apache2')
            self.base_image = self.env.container.commit(repository=image)

    def start(self):
        self.env.execute_command('systemctl start apache2',
                                 environment={'LD_PRELOAD': '/libsslkeylog.so'})
        time.sleep(1)

    def reload(self):
        self.env.execute_command('systemctl reload apache2')

    def create_user(self, username, password):
        self.env.execute_command(f'htpasswd -b /etc/apache2/.htpasswd {username} {password}')
