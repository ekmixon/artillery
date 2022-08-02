#
#
# config module for configuration reading/writing/translating
#
# module is disabled for now as this breaks config reading

import os
import platform
from . import globals

if platform.system() == "Windows":
    import ntpath

import yaml

from src.core import *


def get_config_path():
    path = ""
    # ToDo: Support for command line argument pointing to config file.
    if is_posix() and os.path.isfile(globals.g_configfile):
        path = globals.g_configfile
    if is_windows():
        program_files = os.environ["PROGRAMFILES(X86)"]
        if os.path.isfile(globals.g_configfile):
            path = globals.g_configfile
    return path


def read_config(param):
    path = get_config_path()
    if is_windows():
        name = ntpath.basename(path)
    elif is_posix():
        dirs, name = os.path.split(path)

    exten = name.split(".")[-1]

    if ((not exten) or (exten == 'ini')):
        return read_config_ini(path, param)
    elif (exten == 'yaml'):
        return read_config_yaml(path, param)

    return ""


def read_config_ini(path, param):
    fileopen = file(path, "r")
    for line in fileopen:
        if not line.startswith("#"):
            if match := re.search(f"{param}=", line):
                line = line.rstrip()
                line = line.replace('"', "")
                line = line.split("=")
                return line[1]


def read_config_yaml(path, param):
    with open(path, "r") as fileopen:
        configTree = yaml.safe_load(fileopen)
    if (configTree):
        return configTree.get(param, None)


def is_config_enabled(param):
    config = read_config(param).lower()
    return config in ("on", "yes", "true")
