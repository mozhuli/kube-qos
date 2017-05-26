/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bandwidth

import (
	"errors"
)

type FakeShaper struct {
	CIDRs      []string
	ResetCIDRs []string
}

func (f *FakeShaper) Limit(cidr, rate, ifb string) error {
	return errors.New("unimplemented")
}

func (f *FakeShaper) ReconcileInterface(vethName, upload, download string) error {
	return errors.New("unimplemented")
}

func (f *FakeShaper) ReconcileCIDR(cidr, egress, ingress string) error {
	return errors.New("unimplemented")
}
