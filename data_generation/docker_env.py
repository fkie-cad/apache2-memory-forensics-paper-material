import subprocess
from pathlib import Path
import docker
import tarfile


class DockerEnv:

    def __init__(self, path_to_dockerfile=None, image=None, from_image=True, delete_image=False,
                 container_name=None, stop_container=True, ports=None):
        self.from_image = from_image
        self.dockerfile = path_to_dockerfile
        self.image = image
        self.client = docker.from_env()
        self.delete_image = delete_image
        self.container_name = container_name
        self.stop_container = stop_container
        self.ports = ports

    def __enter__(self):
        if self.from_image and self.image:
            if self.container_name:
                name = self.container_name
            elif type(self.image) == str:
                name = self.image
            else:
                name = self.image.attrs['RepoTags'][0].split(':')[0]
            self.container = \
                self.client.containers.run(image=self.image, detach=True, command="/bin/bash",
                                           tty=True, privileged=True, name=name,
                                           ports=self.ports)
        else:
            print('    Building image from dockerfile ...')
            self.client.images.build(path='.', tag='dockerfile', rm=True, nocache=True)
            self.container = self.client.containers.run(image='dockerfile:latest', detach=True,
                                                        command="/bin/bash", tty=True,
                                                        privileged=True, ports=self.ports)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.stop_container:
            self.container.stop()
            self.container.remove()
            if self.delete_image:
                self.client.images.remove(self.container.image.attrs['RepoTags'][0])

    def upload_files(self, path_to_files, dest_path):
        with tarfile.open(Path('/tmp/upload.tar'), "w:gz") as tar:
            tar.add(path_to_files, arcname=f'/tmp/upload')
        with open(Path('/tmp/upload.tar').resolve(), 'rb') as tar:
            self.container.put_archive(path='.', data=tar.read())
        if Path("/tmp/upload.tar").exists():
            Path("/tmp/upload.tar").unlink()
        self.execute_command(f'mv /tmp/upload {dest_path}')

    def download_files(self, src_path, dest_path):
        with open('/tmp/download.tar', "wb") as tar:
            stream, info = self.container.get_archive(path=f'{src_path}')
            for data_stream in stream:
                tar.write(data_stream)
        with tarfile.open('/tmp/download.tar') as tar:
            tar.extractall('/tmp/docker_download/')

        for extracted_path in Path('/tmp/docker_download/').glob('*'):
            if extracted_path.is_dir():
                if not Path(dest_path).parent.exists():
                    Path(dest_path).parent.mkdir()
                extracted_path.rename(dest_path)
            else:
                if not Path(dest_path).parent.exists():
                    Path(dest_path).parent.mkdir()
                extracted_path.rename(dest_path)

        subprocess.call('rm -rf /tmp/docker_download/', shell=True)
        subprocess.call('rm /tmp/download.tar', shell=True)

    def delete(self, path):
        self.execute_command(f'rm -f {path}')

    def execute_command(self, cmd, detach=False, environment=None):
        msg = self.container.exec_run(cmd, stream=True, detach=detach,
                                      environment=environment)
        tmp_string = b''
        for line in msg.output:
            tmp_string += line
        print(tmp_string.decode('utf-8').strip('\n'))
