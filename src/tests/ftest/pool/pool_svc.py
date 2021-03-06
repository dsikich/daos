#!/usr/bin/python
'''
  (C) Copyright 2018-2021 Intel Corporation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
'''
from __future__ import print_function
import traceback

from apricot import TestWithServers
from test_utils_pool import TestPool
from avocado.core.exceptions import TestFail

RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"


class PoolSvc(TestWithServers):
    """
    Tests svc argument while pool create.
    :avocado: recursive
    """

    def test_poolsvc(self):
        """
        Test svc arg during pool create.

        :avocado: tags=all,pool,daily_regression,medium,svc,DAOS_5610
        """
        # parameter used in pool create
        createsvc = self.params.get("svc", '/run/createtests/createsvc/*/')

        expected_result = createsvc[1]

        # initialize a python pool object then create the underlying
        # daos storage
        self.pool = TestPool(self.context, self.get_dmg_command())
        self.pool.get_params(self)
        self.pool.svcn.update(createsvc[0])
        try:
            self.pool.create()
            if expected_result == RESULT_FAIL:
                self.fail("Test was expected to fail, but it passed.\n")
        except TestFail as excep:
            print("## TestFail exception is caught at pool create!")
            print(excep)
            print(traceback.format_exc())
            if expected_result == RESULT_PASS:
                self.fail("Test was expected to pass but it failed.\n")

        # FAIL case should fail at above pool create, so do below only for
        # PASS case
        if expected_result == RESULT_PASS:
            self.log.debug("self.pool.svc_ranks = %s", self.pool.svc_ranks)
            self.assertTrue(999999 not in self.pool.svc_ranks,
                            "999999 is in the pool's service ranks.")
            self.assertEqual(len(self.pool.svc_ranks), self.pool.svcn.value,
                             "Length of Returned Rank list is not equal to " +
                             "the number of Pool Service members.")

            # Verify there are no duplicate ranks in the rank list
            self.assertEqual(len(self.pool.svc_ranks),
                             len(set(self.pool.svc_ranks)),
                             "Duplicate values in returned rank list")

            try:
                self.pool.get_info()
                leader = self.pool.info.pi_leader
                if createsvc[0] == 3:
                    # kill pool leader and exclude it
                    self.pool.pool.pool_svc_stop()
                    self.pool.exclude([leader], self.d_log)
                    # perform pool disconnect, try connect again and disconnect
                    self.pool.disconnect()
                    self.pool.connect()
                    self.pool.disconnect()
                    # kill another server which is not a leader and exclude it
                    self.server_managers[0].stop_ranks([3], self.test_log)
                    self.pool.exclude([3], self.d_log)
                    # perform pool connect
                    self.pool.connect()
            # Use TestFail instead of DaosApiError because create method has
            # @fail_on
            except TestFail as excep:
                print("## TestFail exception caught")
                print(excep)
                print(traceback.format_exc())
                self.fail("Test was expected to pass but it failed.\n")
