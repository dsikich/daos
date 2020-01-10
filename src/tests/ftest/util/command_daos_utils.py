#!/usr/bin/python
"""
  (C) Copyright 2018-2019 Intel Corporation.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
  The Government's rights to use, modify, reproduce, release, perform, display,
  or disclose this software are subject to the terms of the Apache License as
  provided in Contract No. B609815.
  Any reproduction of computer software, computer software documentation, or
  portions thereof marked with this legend must also reproduce the markings.
"""
from logging import getLogger

import os
import re
import time
import yaml

from command_utils import (CommandFailure, BasicParameter, ObjectWithParameters,
                           CommandWithSubCommand)
from general_utils import check_file_exists, stop_processes

# pylint: disable=unused-import
# Supported JobManager classes for SubprocessManager.__init__()
from job_manager_utils import OpenMPI, Mpich, Srun
# pylint: enable=unused-import


class AccessPoints(object):
    # pylint: disable=too-few-public-methods
    """Defines an object for storing access point data."""

    def __init__(self, port=10001):
        """Initialize a AccessPoints object.

        Args:
            port (int, optional): port number. Defaults to 10001.
        """
        self.hosts = []
        self.port = port

    def __str__(self):
        """Return a comma-separated list of <host>:<port>."""
        return ",".join(
            [":".join([host, str(self.port)]) for host in self.hosts])


class YamlParameters(ObjectWithParameters):
    """A class of parameters used to create a yaml file."""

    def __init__(self, namespace, filename=None, title=None, other_params=None):
        """Create a YamlParameters object.

        Args:
            namespace (str): yaml namespace (path to parameters)
            filename (str): the yaml file to generate with the parameters
            title (str, optional): namespace under which to place the
                parameters when creating the yaml file. Defaults to None.
            other_params (YamlParameters, optional): yaml parameters to
                include with these yaml parameters. Defaults to None.
        """
        super(YamlParameters, self).__init__(namespace)
        self.filename = filename
        self.title = title
        self.other_params = other_params

    def get_yaml_data(self):
        """Convert the parameters into a dictionary to use to write a yaml file.

        Returns:
            dict: a dictionary of parameter name keys and values

        """
        # All log files should be placed in the same directory on each host to
        # enable easy log file archiving by launch.py
        log_dir = os.environ.get("DAOS_TEST_LOG_DIR", "/tmp")

        if isinstance(self.other_params, YamlParameters):
            yaml_data = self.other_params.get_yaml_data()
        else:
            yaml_data = {}
        for name in self.get_param_names():
            value = getattr(self, name).value
            if value is not None and value is not False:
                if name.endswith("log_file"):
                    # Log files are expected to defined in the test yaml by name
                    # only.  The command's yaml file needs the file's full path.
                    yaml_data[name] = os.path.join(
                        log_dir, os.path.basename(value))
                else:
                    yaml_data[name] = value

        return yaml_data if self.title is None else {self.title: yaml_data}

    def create_yaml(self):
        """Create a yaml file from the parameter values.

        Raises:
            CommandFailure: if there is an error creating the yaml file

        """
        yaml_data = self.get_yaml_data()
        self.log.info("Writing yaml configuration file %s", self.filename)
        try:
            with open(self.filename, 'w') as write_file:
                yaml.dump(yaml_data, write_file, default_flow_style=False)
        except Exception as error:
            raise CommandFailure(
                "Error writing the yaml file {}: {}".format(
                    self.filename, error))

    def get_value(self, name):
        """Get the value of the specified attribute name.

        Args:
            name (str): name of the attribute from which to get the value

        Returns:
            object: the object's value referenced by the attribute name

        """
        setting = getattr(self, name, None)
        if setting is not None and isinstance(setting, BasicParameter):
            value = setting.value
        elif setting is not None:
            value = setting
        elif self.other_params is not None:
            value = self.other_params.get_value(name)
        else:
            value = None
        return value


class TransportCredentials(YamlParameters):
    """Transport credentials listing certificates for secure communication."""

    def __init__(self, namespace, title):
        """Initialize a TransportConfig object.

        Args:
            namespace (str): yaml namespace (path to parameters)
            title (str, optional): namespace under which to place the
                parameters when creating the yaml file. Defaults to None.
        """
        super(TransportCredentials, self).__init__(namespace, None, title)

        # Transport credential parameters:
        #   - allow_insecure: false|true
        #       Specify 'false' to bypass loading certificates and use insecure
        #       communications channnels
        #
        #   - ca_cert: <file>, e.g. ".daos/daosCA.crt"
        #       Custom CA Root certificate for generated certs
        #
        #   - cert: <file>, e.g. ".daos/daos_agent.crt"
        #       Agent certificate for use in TLS handshakes
        #
        #   - key: <file>, e.g. ".daos/daos_agent.key"
        #       Key portion of Server Certificate
        #
        self.allow_insecure = BasicParameter(True, True)
        self.ca_cert = BasicParameter(None)
        self.cert = BasicParameter(None)
        self.key = BasicParameter(None)

    def get_yaml_data(self):
        """Convert the parameters into a dictionary to use to write a yaml file.

        Returns:
            dict: a dictionary of parameter name keys and values

        """
        yaml_data = super(TransportCredentials, self).get_yaml_data()

        # Convert the boolean value into a string
        if self.title is not None:
            yaml_data[self.title]["allow_insecure"] = self.allow_insecure.value
        else:
            yaml_data["allow_insecure"] = self.allow_insecure.value

        return yaml_data


class CommonConfig(YamlParameters):
    """Defines common daos_agent and daos_server configuration file parameters.

    Includes:
        - the daos system name (name)
        - a list of access point nodes (access_points)
        - the default port number (port)
        - the transport credentials
    """

    def __init__(self, name, transport):
        """Initialize a CommonConfig object.

        Args:
            name (str): default value for the name configuration parameter
            transport (TransportCredentials): transport credentails
        """
        super(CommonConfig, self).__init__(
            "/run/common_config/*", None, None, transport)

        # Common configuration paramters
        #   - name: <str>, e.g. "daos_server"
        #       Name associated with the DAOS system.
        #
        #   - access_points: <list>, e.g.  ["hostname1:10001"]
        #       Hosts can be specified with or without port, default port below
        #       assumed if not specified. Defaults to the hostname of this node
        #       at port 10000 for local testing
        #
        #   - port: <int>, e.g. 10001
        #       Default port number with whith to bind the daos_server. This
        #       will also be used when connecting to access points if the list
        #       only contains host names.
        #
        self.name = BasicParameter(None, name)
        self.access_points = AccessPoints(10001)
        self.port = BasicParameter(None, 10001)

    def update_hosts(self, hosts):
        """Update the list of hosts for the access point.

        Args:
            hosts (list): list of access point hosts
        """
        if isinstance(hosts, list):
            self.access_points.hosts = [host for host in hosts]
        else:
            self.access_points.hosts = []

    def get_params(self, test):
        """Get values for starting agents and server from the yaml file.

        Obtain the lists of hosts from the BasicParameter class attributes.

        Args:
            test (Test): avocado Test object
        """
        # Get the common parameters: name & port
        super(CommonConfig, self).get_params(test)
        self.access_points.port = self.port.value

        # Get the transport credentials parameters
        self.other_params.get_params(test)

    def get_yaml_data(self):
        """Convert the parameters into a dictionary to use to write a yaml file.

        Returns:
            dict: a dictionary of parameter name keys and values

        """
        yaml_data = super(CommonConfig, self).get_yaml_data()
        yaml_data.pop("pmix", None)

        # For now only include the first host in the access point list
        if self.access_points.hosts:
            yaml_data["access_points"] = [
                ":".join([host, str(self.port.value)])
                for host in self.access_points.hosts[:1]
            ]

        return yaml_data


class SubProcessCommand(CommandWithSubCommand):
    """A class for a command run as a subprocess with a sub command.

    Example commands: daos_agent, daos_server
    """

    def __init__(self, namespace, command, path="", timeout=60):
        """Create a SubProcessCommand object.

        Args:
            namespace (str): yaml namespace (path to parameters)
            command (str): string of the command to be executed.
            path (str, optional): path to location of command binary file.
                Defaults to "".
            timeout (int, optional): number of seconds to wait for patterns to
                appear in the subprocess output. Defaults to 60 seconds.
        """
        super(SubProcessCommand, self).__init__(namespace, command, path, True)

        # Attributes used to determine command success when run as a subprocess
        # See self.check_subprocess_status() for details.
        self.timeout = timeout
        self.pattern = None
        self.pattern_count = 1

    def check_subprocess_status(self, sub_process):
        """Verify the status of the command started as a subprocess.

        Continually search the subprocess output for a pattern (self.pattern)
        until the expected number of patterns (self.pattern_count) have been
        found (typically one per host) or the timeout (self.timeout) is reached
        or the process has stopped.

        Args:
            sub_process (process.SubProcess): subprocess used to run the command

        Returns:
            bool: whether or not the command progress has been detected

        """
        status = True
        self.log.info(
            "Checking status of the %s command in %s with a %s second timeout",
            self._command, sub_process, self.timeout)

        if self.pattern is not None:
            pattern_matches = 0
            timed_out = False
            status = False
            start_time = time.time()

            # Search for patterns in the subprocess output until:
            #   - the expected number of pattern matches are detected (success)
            #   - the time out is reached (failure)
            #   - the subprocess is no longer running (failure)
            while not status and not timed_out and sub_process.poll() is None:
                output = sub_process.get_stdout()
                pattern_matches = len(re.findall(self.pattern, output))
                status = pattern_matches == self.pattern_count
                timed_out = time.time() - start_time > self.timeout

            if not status:
                # Report the error / timeout
                err_msg = "{} detected. Only {}/{} messages received".format(
                    "Time out" if timed_out else "Error",
                    pattern_matches, self.pattern_count)
                self.log.info("%s:\n%s", err_msg, sub_process.get_stdout())

                # Stop the timed out process
                if timed_out:
                    self.stop()
            else:
                # Report the successful start
                self.log.info(
                    "%s subprocess started in %f seconds",
                    self._command, time.time() - start_time)

        return status


class YamlCommand(SubProcessCommand):
    """Defines a sub-process command that utilizes a yaml configuration file.

    Example commands: daos_agent, daos_server
    """

    def __init__(self, namespace, command, path="", yaml_cfg=None, timeout=60):
        """Create a YamlCommand command object.

        Args:
            namespace (str): yaml namespace (path to parameters)
            command (str): string of the command to be executed.
            yaml_cfg (YamlParameters, optional): yaml configuration parameters.
                Defaults to None.
            path (str, optional): path to location of daos command binary.
                Defaults to ""
            timeout (int, optional): number of seconds to wait for patterns to
                appear in the subprocess output. Defaults to 60 seconds.
        """
        super(YamlCommand, self).__init__(namespace, command, path)

        # Command configuration yaml file
        self.yaml = yaml_cfg

    def get_params(self, test):
        """Get values for the daos command and its yaml config file.

        Args:
            test (Test): avocado Test object
        """
        super(YamlCommand, self).get_params(test)
        if isinstance(self.yaml, YamlParameters):
            self.yaml.get_params(test)
            self.yaml.create_yaml()

    def get_config_value(self, name):
        """Get the value of the yaml configuration parameter name.

        Args:
            name (str): name of the yaml configuration parameter from which to
                get the value

        Returns:
            object: the yaml configuration parameter value or None

        """
        value = None
        if isinstance(self.yaml, YamlParameters):
            value = self.yaml.get_value(name)
        return value

    @property
    def access_points(self):
        """Get the access points used with this command.

        Returns:
            AccessPoints: an object with the list of hosts and ports that serve
                as access points for the command.

        """
        value = None
        if isinstance(self.yaml, YamlParameters):
            value = self.yaml.get_config_value("access_points")
        return value


class SubprocessManager(object):
    """Defines an object that manages a sub process launched with orterun."""

    def __init__(self, command, manager="OpenMPI"):
        """Create a SubprocessManager object.

        Args:
            command (YamlCommand): command to manage as a subprocess
            manager (str, optional): the name of the JobManager class used to
                manage the YamlCommand defined through the "job" attribute.
                Defaults to "OpenMpi"
        """
        self.log = getLogger(__name__)

        # Define the JobManager class used to manage the command as a subprocess
        if manager not in globals():
            raise CommandFailure(
                "Invalid job manager class: {}".format(manager))
        self.manager = globals()[manager](command, subprocess=True)

        # Define the list of hosts that will execute the daos command
        self._hosts = []

        # Define the list of executable names to terminate in the kill() method
        self._exe_names = [self.manager.job.command]

    @property
    def hosts(self):
        """Get the hosts used to execute the daos command."""
        return self._hosts

    @hosts.setter
    def hosts(self, value):
        """Set the hosts used to execute the daos command.

        Args:
            value (tuple): a tuple of a list of hosts, a path in which to create
                the hostfile, and a number of slots to specify per host in the
                hostfile (can be None)
        """
        self._set_hosts(*value)

    def _set_hosts(self, hosts, path, slots):
        """Set the hosts used to execute the daos command.

        Defined as a private method to enable overriding the setter method.

        Args:
            hosts (list): list of hosts on which to run the command
            path (str): path in which to create the hostfile
            slots (int): number of slots per host to specify in the hostfile
        """
        self._hosts = hosts
        self.manager.assign_hosts(self._hosts, path, slots)
        self.manager.assign_processes(len(self._hosts))

    def get_params(self, test):
        """Get values for all of the command params from the yaml file.

        Use the yaml file paramter values to assign the server command and
        orterun command parameters.

        Args:
            test (Test): avocado Test object
        """
        # Get the parameters for the JobManager command parameters
        self.manager.get_params(test)

        # Get the values for the job parameters
        self.manager.job.get_params(test)

    def start(self):
        """Start the daos command.

        Raises:
            CommandFailure: if the daos command fails to start

        """
        try:
            self.manager.run()
        except CommandFailure:
            # Kill the subprocess, anything that might have started
            self.kill()
            raise CommandFailure(
                "Failed to start {}.".format(str(self.manager.job)))

    def stop(self):
        """Stop the daos command."""
        self.manager.stop()

    def kill(self):
        """Forcably terminate any sub process running on hosts."""
        stop_processes(self._hosts, "'({})'".format("|".join(self._exe_names)))

    def verify_socket_directory(self, user):
        """Verify the domain socket directory is present and owned by this user.

        Args:
            user (str): user to verify has ownership of the directory

        Raises:
            CommandFailure: if the socket directory does not exist or is not
                owned by the user

        """
        if self._hosts and hasattr(self.manager.job, "yaml"):
            directory = self.get_user_file()
            status, nodes = check_file_exists(self._hosts, directory, user)
            if not status:
                raise CommandFailure(
                    "{}: Server missing socket directory {} for user {}".format(
                        nodes, directory, user))

    def get_config_value(self, name):
        """Get the value of the yaml configuration parameter name.

        Args:
            name (str): name of the yaml configuration parameter from which to
                get the value

        Returns:
            object: the yaml configuration parameter value or None

        """
        value = None
        if self.manager.job and hasattr(self.manager.job, "get_config_value"):
            value = self.manager.job.get_config_value(name)
        return value

    def get_user_file(self):
        """Get the file defined in the yaml file that must be owned by the user.

        Returns:
            str: file defined in the yaml file that must be owned by the user

        """
        return self.get_config_value("socket_dir")