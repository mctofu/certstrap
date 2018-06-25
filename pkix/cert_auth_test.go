/*-
 * Copyright 2015 Square Inc.
 * Copyright 2014 CoreOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pkix

import (
	"testing"
	"time"
)

func TestCreateCertificateAuthority(t *testing.T) {
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	zero := 0
	one := 1
	tests := []struct {
		expectMaxPathLen     int
		expectMaxPathLenZero bool
		pathLength           *int
	}{
		{-1, false, nil},
		{0, true, &zero},
		{1, false, &one},
	}

	for _, test := range tests {
		crt, err := CreateCertificateAuthority(key, "OU", time.Now().AddDate(5, 0, 0), "test", "US", "California", "San Francisco", "CA Name", test.pathLength)
		if err != nil {
			t.Fatal("Failed creating certificate authority:", err)
		}
		rawCrt, err := crt.GetRawCertificate()
		if err != nil {
			t.Fatal("Failed to get x509.Certificate:", err)
		}

		if err = rawCrt.CheckSignatureFrom(rawCrt); err != nil {
			t.Fatal("Failed to check signature:", err)
		}

		if rawCrt.Subject.OrganizationalUnit[0] != "OU" {
			t.Fatal("Failed to verify hostname:", err)
		}

		if !time.Now().After(rawCrt.NotBefore) {
			t.Fatal("Failed to be after NotBefore")
		}

		if !time.Now().Before(rawCrt.NotAfter) {
			t.Fatal("Failed to be before NotAfter")
		}

		if rawCrt.MaxPathLen != test.expectMaxPathLen {
			t.Fatalf("MaxPathLen not correctly set. Expected %d but was %d", test.expectMaxPathLen, rawCrt.MaxPathLen)
		}

		if rawCrt.MaxPathLenZero != test.expectMaxPathLenZero {
			t.Fatal("MaxPathLenZero not correctly set")
		}
	}
}
