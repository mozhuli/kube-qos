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
	"fmt"
)

var minBW = "1kbit"
var maxBW = "1gbit"

func validateBandwidthIsReasonable(bandwidth string) error {
	if bandwidth == minBW {
		return fmt.Errorf("resource is unreasonably small (< 1kbit)")
	}
	if bandwidth == maxBW {
		return fmt.Errorf("resoruce is unreasonably large (> 1gbit)")
	}
	return nil
}

func ExtractPodBandwidthResources(podAnnotations map[string]string) (ingress, egress string, err error) {
	ingress, found := podAnnotations["kubernetes.io/ingress-bandwidth"]
	if found {
		if err := validateBandwidthIsReasonable(ingress); err != nil {
			return "", "", err
		}
	}
	egress, found = podAnnotations["kubernetes.io/egress-bandwidth"]
	if found {
		if err := validateBandwidthIsReasonable(egress); err != nil {
			return "", "", err
		}
	}
	return ingress, egress, nil
}
