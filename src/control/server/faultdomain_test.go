//
// (C) Copyright 2020-2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"

	"github.com/daos-stack/daos/src/control/common"
	"github.com/daos-stack/daos/src/control/server/config"
	"github.com/daos-stack/daos/src/control/system"
)

func assertFaultDomainEqualStr(t *testing.T, expResultStr string, result *system.FaultDomain) {
	if expResultStr == "" {
		if result != nil {
			t.Fatalf("expected nil result, got %q", result.String())
		}
	} else {
		common.AssertEqual(t, expResultStr, result.String(), "incorrect fault domain")
	}
}

func TestServer_getDefaultFaultDomain(t *testing.T) {
	for name, tc := range map[string]struct {
		getHostname hostnameGetterFn
		expResult   string
		expErr      error
	}{
		"hostname returns error": {
			getHostname: func() (string, error) {
				return "", errors.New("mock hostname")
			},
			expErr: errors.New("mock hostname"),
		},
		"success": {
			getHostname: func() (string, error) {
				return "myhost", nil
			},
			expResult: "/myhost",
		},
		"hostname not usable": {
			getHostname: func() (string, error) {
				return "/////////", nil
			},
			expErr: config.FaultConfigFaultDomainInvalid,
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := getDefaultFaultDomain(tc.getHostname)

			common.CmpErr(t, tc.expErr, err)
			assertFaultDomainEqualStr(t, tc.expResult, result)
		})
	}
}

func TestServer_getFaultDomain(t *testing.T) {
	realHostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("couldn't get hostname: %s", err)
	}

	tmpDir, cleanup := common.CreateTestDir(t)
	defer cleanup()

	validFaultDomain := "/host0"
	cbScriptPath := filepath.Join(tmpDir, "cb.sh")
	createFaultCBScriptFile(t, cbScriptPath, 0755, validFaultDomain)

	for name, tc := range map[string]struct {
		cfg       *config.Server
		expResult string
		expErr    error
	}{
		"nil cfg": {
			expErr: config.FaultBadConfig,
		},
		"cfg fault path": {
			cfg: &config.Server{
				FaultPath: validFaultDomain,
			},
			expResult: validFaultDomain,
		},
		"cfg fault path is not valid": {
			cfg: &config.Server{
				FaultPath: "junk",
			},
			expErr: config.FaultConfigFaultDomainInvalid,
		},
		"root-only path is not valid": {
			cfg: &config.Server{
				FaultPath: "/",
			},
			expErr: config.FaultConfigFaultDomainInvalid,
		},
		"too many layers": { // TODO DAOS-6353: change when multiple layers supported
			cfg: &config.Server{
				FaultPath: "/rack1/host0",
			},
			expErr: config.FaultConfigTooManyLayersInFaultDomain,
		},
		"cfg fault callback": {
			cfg: &config.Server{
				FaultCb: cbScriptPath,
			},
			expResult: validFaultDomain,
		},
		"cfg fault callback is not valid": {
			cfg: &config.Server{
				FaultCb: filepath.Join(tmpDir, "does not exist"),
			},
			expErr: config.FaultConfigFaultCallbackNotFound,
		},
		"cfg both fault path and fault CB": {
			cfg: &config.Server{
				FaultPath: validFaultDomain,
				FaultCb:   cbScriptPath,
			},
			expErr: config.FaultConfigBothFaultPathAndCb,
		},
		"default gets hostname": {
			cfg:       &config.Server{},
			expResult: system.FaultDomainSeparator + realHostname,
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := getFaultDomain(tc.cfg)

			common.CmpErr(t, tc.expErr, err)
			assertFaultDomainEqualStr(t, tc.expResult, result)
		})
	}
}

func createFaultCBScriptFile(t *testing.T, path string, mode os.FileMode, output string) {
	t.Helper()

	createScriptFile(t, path, mode, fmt.Sprintf("echo %q\n", output))
}

func createErrorScriptFile(t *testing.T, path string) {
	t.Helper()

	badPath := filepath.Join(path, "invalid") // making an impossible path out of our script's path
	createScriptFile(t, path, 0755, fmt.Sprintf("ls %s\n", badPath))
}

func createScriptFile(t *testing.T, path string, mode os.FileMode, content string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create script file %q: %s", path, err)
	}

	_, err = f.WriteString(fmt.Sprintf("#!/bin/bash\n\n%s\n", content))
	if err != nil {
		t.Fatalf("failed to write to script file %q: %s", path, err)
	}

	err = f.Chmod(mode)
	if err != nil {
		t.Fatalf("failed to update mode of script file %q to %d: %s", path, mode, err)
	}

	f.Close()
}

func TestServer_getFaultDomainFromCallback(t *testing.T) {
	tmpDir, cleanup := common.CreateTestDir(t)
	defer cleanup()

	validFaultDomain := "/myfaultdomain"

	goodScriptPath := filepath.Join(tmpDir, "good.sh")
	createFaultCBScriptFile(t, goodScriptPath, 0755, validFaultDomain)

	badPermsScriptPath := filepath.Join(tmpDir, "noPerms.sh")
	createFaultCBScriptFile(t, badPermsScriptPath, 0600, validFaultDomain)

	errorScriptPath := filepath.Join(tmpDir, "fail.sh")
	createErrorScriptFile(t, errorScriptPath)

	emptyScriptPath := filepath.Join(tmpDir, "empty.sh")
	createFaultCBScriptFile(t, emptyScriptPath, 0755, "")

	whitespaceScriptPath := filepath.Join(tmpDir, "whitespace.sh")
	createFaultCBScriptFile(t, whitespaceScriptPath, 0755, "     ")

	invalidScriptPath := filepath.Join(tmpDir, "invalid.sh")
	createFaultCBScriptFile(t, invalidScriptPath, 0755, "some junk")

	multiLayerScriptPath := filepath.Join(tmpDir, "multilayer.sh")
	createFaultCBScriptFile(t, multiLayerScriptPath, 0755, "/one/two")

	rootScriptPath := filepath.Join(tmpDir, "rootdomain.sh")
	createFaultCBScriptFile(t, rootScriptPath, 0755, "/")

	for name, tc := range map[string]struct {
		input     string
		expResult string
		expErr    error
	}{
		"empty path": {
			expErr: errors.New("no callback path supplied"),
		},
		"success": {
			input:     goodScriptPath,
			expResult: validFaultDomain,
		},
		"script does not exist": {
			input:  filepath.Join(tmpDir, "notarealfile"),
			expErr: config.FaultConfigFaultCallbackNotFound,
		},
		"script has bad permissions": {
			input:  badPermsScriptPath,
			expErr: config.FaultConfigFaultCallbackBadPerms,
		},
		"error within the script": {
			input:  errorScriptPath,
			expErr: config.FaultConfigFaultCallbackFailed(errors.New("exit status 2")),
		},
		"script returned no output": {
			input:  emptyScriptPath,
			expErr: config.FaultConfigFaultCallbackEmpty,
		},
		"script returned only whitespace": {
			input:  whitespaceScriptPath,
			expErr: config.FaultConfigFaultCallbackEmpty,
		},
		"script returned invalid fault domain": {
			input:  invalidScriptPath,
			expErr: config.FaultConfigFaultDomainInvalid,
		},
		"script returned root fault domain": {
			input:  rootScriptPath,
			expErr: config.FaultConfigFaultDomainInvalid,
		},
		"script returned fault domain with too many layers": { // TODO DAOS-6353: change when multiple layers supported
			input:  multiLayerScriptPath,
			expErr: config.FaultConfigTooManyLayersInFaultDomain,
		},
		"no arbitrary shell commands allowed": {
			input:  "echo \"my dog has fleas\"",
			expErr: config.FaultConfigFaultCallbackNotFound,
		},
		"no command line parameters allowed": {
			input:  fmt.Sprintf("%s arg", goodScriptPath),
			expErr: config.FaultConfigFaultCallbackNotFound,
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := getFaultDomainFromCallback(tc.input)

			common.CmpErr(t, tc.expErr, err)
			assertFaultDomainEqualStr(t, tc.expResult, result)
		})
	}
}
