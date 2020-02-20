#!/usr/bin/python
"""
  (C) Copyright 2020 Intel Corporation.

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
from ClusterShell.NodeSet import NodeSet

from apricot import TestWithServers
from fio_utils import FioCommand
from command_utils_base import CommandFailure, EnvironmentVariables
from dfuse_utils import Dfuse
from daos_utils import create_container


class FioBase(TestWithServers):
    """Base fio class.

    :avocado: recursive
    """

    def __init__(self, *args, **kwargs):
        """Initialize a FioBase object."""
        super(FioBase, self).__init__(*args, **kwargs)
        self.fio_cmd = None
        self.processes = None
        self.manager = None
        self.dfuse = None

    def setUp(self):
        """Set up each test case."""
        # obtain separate logs
        self.update_log_file_names()

        # Start the servers and agents
        super(FioBase, self).setUp()

        # removing runner node from hostlist_client, only need one client node.
        self.hostlist_clients = self.hostlist_clients[:1]
        self.assertEqual(
            len(self.hostlist_clients), 1, "This test requires one client")

        # Get the parameters for Fio
        self.fio_cmd = FioCommand()
        self.fio_cmd.get_params(self)
        self.processes = self.params.get("np", '/run/fio/client_processes/*')
        self.manager = self.params.get("manager", '/run/fio/*', "MPICH")

    def tearDown(self):
        """Tear down each test case."""
        try:
            self.dfuse = None
        finally:
            # Stop the servers and agents
            super(FioBase, self).tearDown()

    def _create_cont(self):
        """Create a TestContainer object to be used to create container."""
        # TO-DO: Enable container using TestContainer object,
        # once DAOS-3355 is resolved.
        # Get Container params
        # self.container = TestContainer(self.pool)
        # self.container.get_params(self)

        # create container
        # self.container.create()

        # command to create container of posix type
        svc = ":".join([str(item) for item in self.pool.svc_ranks])
        env = EnvironmentVariables({"CRT_ATTACH_INFO_PATH": self.tmp})
        result = create_container(self.bin, self.pool.uuid, svc, "POSIX", env)
        if not result:
            self.fail("Container create failed")

        cont_uuid = result.stdout.split()[3]
        self.log.info("Container created with UUID %s", cont_uuid)
        return cont_uuid

    def _start_dfuse(self):
        """Create a DfuseCommand object to start dfuse."""
        # Get Dfuse params
        self.dfuse = Dfuse(self.hostlist_clients, self.tmp, self.basepath)
        self.dfuse.get_params(self)

        # update dfuse params
        self.dfuse.set_dfuse_params(self.pool)
        self.dfuse.set_dfuse_cont_param(self._create_cont())

        try:
            # start dfuse
            self.dfuse.run()
        except CommandFailure as error:
            self.log.error("Dfuse command %s failed on hosts %s",
                           str(self.dfuse), str(
                               NodeSet.fromlist(self.dfuse.hosts)),
                           exc_info=error)
            self.fail("Unable to launch Dfuse.\n")

    def execute_fio(self):
        """Runner method for Fio."""
        # Create a pool if one does not already exist
        if self.pool is None:
            self.add_pool(connect=False)

        # start dfuse if api is POSIX
        if self.fio_cmd.api.value == "POSIX":
            # Connect to the pool, create container and then start dfuse
            # Uncomment below two lines once DAOS-3355 is resolved
            # self.pool.connect()
            # self.create_cont()
            self._start_dfuse()
            self.fio_cmd.update(
                "global", "directory", self.dfuse.mount_dir.value,
                "fio --name=global --directory")

        # Run Fio
        self.fio_cmd.hosts = self.hostlist_clients
        self.fio_cmd.run()
