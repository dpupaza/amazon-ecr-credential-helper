// Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ecr

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation

#include "osxkeychain_darwin.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"regexp"

	"github.com/dpupaza/amazon-ecr-credential-helper/ecr-login/api"
	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"unsafe"
	"net/url"
	"strings"
	"strconv"
)

// errCredentialsNotFound is the specific error message returned by OS X
// when the credentials are not in the keychain.
const errCredentialsNotFound = "The specified item could not be found in the keychain."

const programName = "docker-credential-ecr-login"

var ecrPattern = regexp.MustCompile(`(^[a-zA-Z0-9][a-zA-Z0-9-_]*)\.dkr\.ecr\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.amazonaws\.com(\.cn)?`)
var notImplemented = errors.New("not implemented")

type ECRHelper struct {
	ClientFactory api.ClientFactory
}

func (ECRHelper) Add(creds *credentials.Credentials) error {
	s, err := splitServer(creds.ServerURL)
	if err != nil {
		return err
	}
	defer freeServer(s)

	username := C.CString(creds.Username)
	defer C.free(unsafe.Pointer(username))
	secret := C.CString(creds.Secret)
	defer C.free(unsafe.Pointer(secret))

	errMsg := C.keychain_add(s, username, secret)
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}

	return nil
}

func (ECRHelper) Delete(serverURL string) error {
	s, err := splitServer(serverURL)
	if err != nil {
		return err
	}
	defer freeServer(s)

	errMsg := C.keychain_delete(s)
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		return errors.New(C.GoString(errMsg))
	}

	return nil
}

func (self ECRHelper) Get(serverURL string) (string, string, error) {
	defer log.Flush()
	matches := ecrPattern.FindStringSubmatch(serverURL)
	if len(matches) == 0 {
		log.Debug("Not an ECR registry. Pull credentials from OSX keychain.")
		return getOSXCreds(serverURL)
	} else if len(matches) < 3 {
		log.Error(serverURL + "is not a valid repository URI for Amazon EC2 Container Registry.")
		return "", "", credentials.ErrCredentialsNotFound
	}

	registry := matches[1]
	region := matches[2]
	log.Debugf("Retrieving credentials for %s in %s (%s)", registry, region, serverURL)
	client := self.ClientFactory.NewClient(region)
	user, pass, err := client.GetCredentials(registry, serverURL)
	if err != nil {
		log.Errorf("Error retrieving credentials: %v", err)
		return "", "", credentials.ErrCredentialsNotFound
	}
	return user, pass, nil
}

func (self ECRHelper) List() ([]string, []string, error) {
	var pathsC **C.char
	defer C.free(unsafe.Pointer(pathsC))
	var acctsC **C.char
	defer C.free(unsafe.Pointer(acctsC))
	var listLenC C.uint
	errMsg := C.keychain_list(&pathsC, &acctsC, &listLenC)
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		goMsg := C.GoString(errMsg)
		return nil, nil, errors.New(goMsg)
	}
	var listLen int
	listLen = int(listLenC)
	pathTmp := (*[1 << 30]*C.char)(unsafe.Pointer(pathsC))[:listLen:listLen]
	acctTmp := (*[1 << 30]*C.char)(unsafe.Pointer(acctsC))[:listLen:listLen]
	//taking the array of c strings into go while ignoring all the stuff irrelevant to credentials-helper
	paths := make([]string, listLen)
	accts := make([]string, listLen)
	at := 0
	for i := 0; i < listLen; i++ {
		if C.GoString(pathTmp[i]) == "0" {
			continue
		}
		paths[at] = C.GoString(pathTmp[i])
		accts[at] = C.GoString(acctTmp[i])
		at = at + 1
	}
	paths = paths[:at]
	accts = accts[:at]
	C.freeListData(&pathsC, listLenC)
	C.freeListData(&acctsC, listLenC)
	return paths, accts, nil
}

func splitServer(serverURL string) (*C.struct_Server, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}

	hostAndPort := strings.Split(u.Host, ":")
	host := hostAndPort[0]
	var port int
	if len(hostAndPort) == 2 {
		p, err := strconv.Atoi(hostAndPort[1])
		if err != nil {
			return nil, err
		}
		port = p
	}

	proto := C.kSecProtocolTypeHTTPS
	if u.Scheme != "https" {
		proto = C.kSecProtocolTypeHTTP
	}

	return &C.struct_Server{
		proto: C.SecProtocolType(proto),
		host:  C.CString(host),
		port:  C.uint(port),
		path:  C.CString(u.Path),
	}, nil
}

func freeServer(s *C.struct_Server) {
	C.free(unsafe.Pointer(s.host))
	C.free(unsafe.Pointer(s.path))
}

// Get returns the username and secret to use for a given registry server URL.
func getOSXCreds(serverURL string) (string, string, error) {
	s, err := splitServer(serverURL)
	if err != nil {
		return "", "", err
	}
	defer freeServer(s)

	var usernameLen C.uint
	var username *C.char
	var secretLen C.uint
	var secret *C.char
	defer C.free(unsafe.Pointer(username))
	defer C.free(unsafe.Pointer(secret))

	errMsg := C.keychain_get(s, &usernameLen, &username, &secretLen, &secret)
	if errMsg != nil {
		defer C.free(unsafe.Pointer(errMsg))
		goMsg := C.GoString(errMsg)
		if goMsg == errCredentialsNotFound {
			return "", "", credentials.ErrCredentialsNotFound
		}

		return "", "", errors.New(goMsg)
	}

	user := C.GoStringN(username, C.int(usernameLen))
	pass := C.GoStringN(secret, C.int(secretLen))
	return user, pass, nil
}
