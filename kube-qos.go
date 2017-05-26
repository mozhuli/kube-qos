/*
Copyright 2016 The Kubernetes Authors.

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

// Note: the example only works with the code within the same release/branch.
package main

import (
	"flag"
	"fmt"
	"regexp"
	"time"

	"github.com/golang/glog"
	"github.com/mozhuli/kube-qos/pkg/bandwidth"
	"github.com/mozhuli/kube-qos/pkg/exec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var (
		kubeconfig    string
		endpoint      string
		labelSelector string
		syncDuration  int
	)
	flag.StringVar(&kubeconfig, "kubeconfig", "/etc/kubernetes/kubelet.conf", "absolute path to the kubeconfig file")
	flag.StringVar(&endpoint, "etcd-endpoint", "", "the calico etcd endpoint, e.g. http://10.96.232.136:6666")
	flag.StringVar(&labelSelector, "labelSelector", "", "select pod to limit bandwidth, e.g. qos=open")
	flag.IntVar(&syncDuration, "syncDuration", 10, "sync duration(second)")
	flag.Parse()
	// uses the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	fmt.Println(err)
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// init ifb module
	err = bandwidth.InitIfbModule()
	if err != nil {
		glog.Errorf("Failed init ifb: %v", err)
	}
	//Synchronize bandwidth limits
	for {
		pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{FieldSelector: "spec.nodeName=10.10.101.204", LabelSelector: labelSelector})
		if err != nil {
			glog.Errorf("Failed list pods: %v", err)
		}
		glog.V(4).Infof("There are %d pods need to be limited in the cluster\n", len(pods.Items))
		//used for  checking which tc class isn't used, and del it
		egressPodsCIDRs := []string{}
		ingressPodsCIDRs := []string{}
		for _, pod := range pods.Items {
			ingress, egress, err := bandwidth.ExtractPodBandwidthResources(pod.Annotations)
			if err != nil {
				glog.Errorf("Failed extract pod's bandwidth resources: %v", err)
			}
			if egress == "" && ingress == "" {
				glog.Warning("rate qos has open,but the pod's bandwidth resources haven't setted")
				continue
			}

			cidr := fmt.Sprintf("%s/32", pod.Status.PodIP)
			if egress != "" {
				egressPodsCIDRs = append(egressPodsCIDRs, cidr)
			}
			if ingress != "" {
				ingressPodsCIDRs = append(ingressPodsCIDRs, cidr)
			}
			//fetch pod's vethname from calico's etcd
			e := exec.New()
			//data, err := e.Command("etcdctl", "--endpoint=http://10.96.232.136:6666", "get", "/calico/v1/host/"+pod.Status.HostIP+"/workload/k8s/"+pod.Namespace+"."+pod.Name+"/endpoint/eth0").CombinedOutput()
			data, err := e.Command("curl", "-L", endpoint+"/v2/keys/calico/v1/host/"+pod.Status.HostIP+"/workload/k8s/"+pod.Namespace+"."+pod.Name+"/endpoint/eth0").CombinedOutput()
			if err != nil {
				glog.Errorf("Failed fetch pod %s interface name: %v", pod.Name, err)
			}
			//get the pod's calico vethname
			re, _ := regexp.Compile("cali[a-f0-9]{11}")
			vethName := string(re.Find(data))
			glog.V(4).Infof("pod %s's vethname is %s", pod.Name, vethName)

			shaper := bandwidth.NewTCShaper(vethName)
			//config pod interface  qdisc, and mirror to ifb
			if err := shaper.ReconcileInterface(egress, ingress); err != nil {
				glog.Errorf("Failed to init veth(%s): %v", vethName, err)
			}

			glog.V(4).Infof("reconcile cidr %s with egress bandwidth %s and ingress bandwidth %s ", cidr, egress, ingress)
			if err := shaper.ReconcileCIDR(cidr, egress, ingress); err != nil {
				glog.Errorf("Failed to reconcile CIDR %s: %v", cidr, err)
			}

		}
		if err := bandwidth.DeleteExtraLimits(egressPodsCIDRs, ingressPodsCIDRs); err != nil {
			glog.Errorf("Failed to delete extra limits: %v", err)
		}
		time.Sleep(time.Duration(syncDuration) * time.Second)
	}
}
