// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudapi "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	networkapi "go.datum.net/network/api/v1alpha1"
)

type labState struct {
	Project      string `json:"project"`
	ConsumerNS   string `json:"consumerNS"`
	ConsumerHost string `json:"consumerHost"`
	ProducerNS   string `json:"producerNS"`
	ProducerHost string `json:"producerHost"`
	Destination  string `json:"destination"`
}

func ip(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, output)
	}
	return nil
}

func (f *fixture) assistAttachment(ctx context.Context, name, host, identity string) error {
	attachment := &cloudapi.VPCAttachment{}
	if err := f.api.Get(ctx, client.ObjectKey{Namespace: f.cfg.Namespace, Name: name}, attachment); err != nil {
		return err
	}
	before := attachment.DeepCopy()
	attachment.Status.Node = f.cfg.NodeName
	attachment.Status.HostInterface = host
	if identity != "" {
		attachment.Status.VPC = identity
	}
	if attachment.Status.VPC == "" {
		attachment.Status.VPC = "fixtureprod"
	}
	if attachment.Status.VPCAttachment == "" {
		attachment.Status.VPCAttachment = host
	}
	attachment.Status.ObservedGeneration = attachment.Generation
	for _, condition := range []string{cloudapi.ConditionTypeReady, cloudapi.ConditionTypeProgrammed} {
		meta.SetStatusCondition(&attachment.Status.Conditions, metav1.Condition{Type: condition, Status: metav1.ConditionTrue,
			ObservedGeneration: attachment.Generation, Reason: "QualificationFixture",
			Message: "Isolated Linux fixture created interface and TC chain"})
	}
	return f.api.Status().Patch(ctx, attachment, client.MergeFrom(before))
}

func (f *fixture) addDestination(address string) error {
	f.relayMu.Lock()
	defer f.relayMu.Unlock()
	if f.destinations[address] {
		return nil
	}
	parsed := net.ParseIP(address)
	if parsed == nil || parsed.To4() != nil {
		return fmt.Errorf("fixture destination %q must be IPv6", address)
	}
	for _, args := range [][]string{
		{ipNetNS, ipExec, f.producerNS, "ip", ipAddr, ipAdd, address + "/128", ipDevice, "p0", ipNoDAD},
		{"-6", ipRoute, ipReplace, address + "/128", ipDevice, f.producerHost},
		{"-6", ipRoute, ipReplace, ipTable, relayTable, address + "/128", ipDevice, f.rootDevice},
	} {
		if err := ip(args...); err != nil {
			return err
		}
	}
	if f.cfg.Role == roleProducer {
		if err := ip("-6", ipRoute, ipReplace, ipTable, "801", address+"/128", ipDevice, f.producerHost); err != nil {
			return err
		}
	}
	port := strconv.Itoa(12000 + len(f.destinations))
	script := filepath.Join(filepath.Dir(f.cfg.State), "psc-relay.py")
	for _, transport := range []string{"udp", "tcp"} {
		for _, mode := range []string{"root", roleProducer} {
			args := []string{script, mode, transport, producerGateway, port, address, servicePort, f.rootSource}
			command := "python3"
			if mode == roleProducer {
				args = []string{ipNetNS, ipExec, f.producerNS, "python3", script, mode, transport,
					address, servicePort, producerGateway, port, "-"}
				command = "ip"
			}
			process := exec.CommandContext(context.Background(), command, args...)
			if err := f.startRelay(process); err != nil {
				return err
			}
		}
	}
	f.destinations[address] = true
	log.Printf("shared producer serves %s via root relay port %s", address, port)
	return nil
}

func (f *fixture) followDestinations(ctx context.Context) {
	if f.cfg.Role == roleConsumer {
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			endpoints := &networkapi.ServiceEndpointList{}
			if err := f.api.List(ctx, endpoints, client.InNamespace(f.cfg.Namespace)); err != nil {
				log.Printf("list fixture destinations: %v", err)
				continue
			}
			for _, endpoint := range endpoints.Items {
				if endpoint.Spec.Port == 8443 {
					if err := f.addDestination(endpoint.Spec.Address); err != nil {
						log.Printf("add fixture destination: %v", err)
					}
				}
			}
		}
	}
}

func globalIPv6() (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, address := range addresses {
			parsed, _, err := net.ParseCIDR(address.String())
			if err == nil && parsed.To4() == nil && parsed.IsGlobalUnicast() && !parsed.IsLinkLocalUnicast() {
				return parsed.String(), iface.Name, nil
			}
		}
	}
	return "", "", errors.New("fixture container requires global IPv6 on the fixture underlay")
}

func (f *fixture) startRelay(process *exec.Cmd) error {
	output, err := process.StdoutPipe()
	if err != nil {
		return err
	}
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = process.Process.Kill(); _ = process.Wait() })
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(output)
		marked := false
		for scanner.Scan() {
			text := scanner.Text()
			log.Print(text)
			if !marked && strings.HasPrefix(text, "READY ") {
				marked = true
				close(ready)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("read fixture relay: %v", err)
		}
	}()
	select {
	case <-ready:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("fixture relay did not become ready")
	}
}

func (f *fixture) setupNetwork(ctx context.Context) error {
	if f.cfg.Role == "" || f.cfg.Role == "local" {
		return f.setupLocalNetwork(ctx)
	}
	return f.setupRemoteNetwork(ctx)
}

func (f *fixture) setupLocalNetwork(ctx context.Context) error {
	source, device, err := globalIPv6()
	if err != nil {
		return err
	}
	f.rootSource, f.rootDevice = source, device
	suffix := strconv.Itoa(os.Getpid())
	f.producerNS, f.producerHost = "psc-p-"+suffix, "pscp"+suffix
	f.pinDir = filepath.Join("/sys/fs/bpf", "galactic-psc-qualification-"+suffix)
	if err := os.MkdirAll(f.pinDir, 0755); err != nil {
		return err
	}
	objects, err := attach.Load(f.pinDir)
	if err != nil {
		return fmt.Errorf("load production TC programs: %w", err)
	}
	f.objects = objects
	f.cleanup = append(f.cleanup, func() { _ = objects.Close(); _ = os.RemoveAll(f.pinDir) })
	if err := ip(ipNetNS, ipAdd, f.producerNS); err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = ip(ipNetNS, "del", f.producerNS) })
	for _, args := range [][]string{
		{ipLink, ipAdd, f.producerHost, ipType, ipVeth, ipPeer, ipName, "p0"},
		{ipLink, ipSet, "p0", ipNetNS, f.producerNS},
		{ipLink, ipSet, f.producerHost, "up"},
		{ipAddr, ipAdd, "fd00:da:1::1/64", ipDevice, f.producerHost, ipNoDAD},
		{ipNetNS, ipExec, f.producerNS, "ip", ipLink, ipSet, "lo", "up"},
		{ipNetNS, ipExec, f.producerNS, "ip", ipAddr, ipAdd, "fd00:da:1::2/64", ipDevice, "p0", ipNoDAD},
		{ipNetNS, ipExec, f.producerNS, "ip", ipLink, ipSet, "p0", "up"},
		{ipNetNS, ipExec, f.producerNS, "ip", ipRoute, ipAdd, ipDefault, ipVia, producerGateway},
		{"-6", "rule", ipAdd, "priority", relayTable, "from", source + "/128", ipTable, relayTable},
	} {
		if err := ip(args...); err != nil {
			return err
		}
	}
	f.cleanup = append(f.cleanup, func() { _ = ip("-6", "rule", "del", "priority", relayTable) })
	producerLink, err := net.InterfaceByName(f.producerHost)
	if err != nil {
		return err
	}
	if err := attach.AttachEgressWithIdentity(objects.UsidServiceEgress, objects.UsidEgress,
		objects.AttachmentIdentityTable, uint32(producerLink.Index), f.producerHost); err != nil {
		return err
	}
	producerName := f.cfg.Cases[0].ProducerAttachment
	if producerName == "" || producerName != f.cfg.Cases[1].ProducerAttachment {
		return errors.New("cases require one shared producer attachment")
	}
	if err := f.assistAttachment(ctx, producerName, f.producerHost, ""); err != nil {
		return err
	}
	for index, entry := range f.cfg.Cases {
		letter := string(rune('a' + index))
		lab := labState{Project: entry.Project, ConsumerNS: "psc-c-" + letter + suffix,
			ConsumerHost: "pscc" + letter + suffix,
			ProducerNS:   f.producerNS, ProducerHost: f.producerHost, Destination: entry.Destination}
		gateway := "fd00:ca:" + strconv.Itoa(index+1) + "::1"
		if err := ip(ipNetNS, ipAdd, lab.ConsumerNS); err != nil {
			return err
		}
		ns := lab.ConsumerNS
		f.cleanup = append(f.cleanup, func() { _ = ip(ipNetNS, "del", ns) })
		for _, args := range [][]string{
			{ipLink, ipAdd, lab.ConsumerHost, ipType, ipVeth, ipPeer, ipName, "c0"},
			{ipLink, ipSet, "c0", ipNetNS, lab.ConsumerNS},
			{ipLink, ipSet, lab.ConsumerHost, "up"},
			{ipAddr, ipAdd, gateway + "/64", ipDevice, lab.ConsumerHost, ipNoDAD},
			{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipLink, ipSet, "lo", "up"},
			{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipAddr, ipAdd, consumerCIDR, ipDevice, "c0", ipNoDAD},
			{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipLink, ipSet, "c0", "up"},
			{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipRoute, ipAdd, gateway + "/128", ipDevice, "c0"},
			{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipRoute, ipAdd, "fd70:ffff::10/128", ipVia, gateway},
		} {
			if err := ip(args...); err != nil {
				return err
			}
		}
		consumerLink, err := net.InterfaceByName(lab.ConsumerHost)
		if err != nil {
			return err
		}
		if err := attach.AttachEgressWithIdentity(objects.UsidServiceEgress, objects.UsidEgress,
			objects.AttachmentIdentityTable, uint32(consumerLink.Index), lab.ConsumerHost); err != nil {
			return err
		}
		if err := f.assistAttachment(ctx, entry.ConsumerAttachment, lab.ConsumerHost, entry.VPCIdentity); err != nil {
			return err
		}
		if err := f.addDestination(entry.Destination); err != nil {
			return err
		}
		f.labs = append(f.labs, lab)
	}
	return nil
}
