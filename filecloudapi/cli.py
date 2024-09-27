# Copyright (c) 2024 FileCloud. All Rights Reserved.
"""
This module provides a command-line interface (CLI) for interacting with the FileCloud API.
Commands:
    upload-file: Uploads a file to the specified remote location on the FileCloud server.
Usage:
    To use the CLI, run the script and follow the prompts for username, password, and server URL.
    Example:
        python cli.py upload-file <local_file_path> <remote_file_path>
    The `upload-file` command requires the following arguments:
        local: The path to the local file to be uploaded.
        remote: The remote path where the file should be uploaded on the FileCloud server.
    Global options:
        --username: Username for authentication.
        --password: Password for authentication (can be set via the FILECLOUD_PASSWORD environment variable).
        --server-url: URL of the FileCloud server.
"""

from dataclasses import dataclass
from pathlib import Path
import click
import os

from filecloudapi.fcserver import FCServer

@dataclass
class ServerConfig:
    server_url: str
    username: str
    password: str

@click.option('-s', '--server-url', prompt=True, hide_input=False, help='URL of the FileCloud server') 
@click.option('-u', '--username', prompt=True, hide_input=False, help='Username for authentication')
@click.option('-p', '--password', prompt=True, hide_input=True, default=lambda: os.environ.get('FILECLOUD_PASSWORD', ''), help='Password for authentication')
@click.group()
@click.pass_context
def cli(ctx, server_url: str, username: str, password: str):
    ctx.obj = ServerConfig(server_url, username, password)
    pass

def create_fcserver(config: ServerConfig) -> FCServer:
    return FCServer(config.server_url, email=None, username=config.username, password=config.password)

@cli.command()
@click.option('-l', '--local', type=Path, required=True, help='Path to the local file to be uploaded')
@click.option('-r', '--remote', type=str, required=True, help='Remote path where the file should be uploaded on the FileCloud server')
@click.pass_obj
def upload_file(config: ServerConfig, local: Path, remote: str):
    fcserver = create_fcserver(config)
    fcserver.upload_file(local, remote)


if __name__ == '__main__':  # pragma: no cover
    cli()
