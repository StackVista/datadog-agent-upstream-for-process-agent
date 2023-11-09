// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package probe holds probe related files
package probe

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/mailru/easyjson"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/DataDog/ebpf-manager/tracefs"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	aconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf/kernel"
	"github.com/DataDog/datadog-agent/pkg/security/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	pconfig "github.com/DataDog/datadog-agent/pkg/security/probe/config"
	"github.com/DataDog/datadog-agent/pkg/security/probe/erpc"
	"github.com/DataDog/datadog-agent/pkg/security/probe/eventstream"
	"github.com/DataDog/datadog-agent/pkg/security/probe/kfilters"
	"github.com/DataDog/datadog-agent/pkg/security/probe/managerhelper"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/netns"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/path"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/process"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/dump"
	"github.com/DataDog/datadog-agent/pkg/security/serializers"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	utilkernel "github.com/DataDog/datadog-agent/pkg/util/kernel"
)

// EventStream describes the interface implemented by reordered perf maps or ring buffers
type EventStream interface {
	Init(*manager.Manager, *pconfig.Config) error
	SetMonitor(eventstream.LostEventCounter)
	Start(*sync.WaitGroup) error
	Pause() error
	Resume() error
}

var (
	// defaultEventTypes event types used whatever the event handlers or the rules
	defaultEventTypes = []eval.EventType{
		model.ForkEventType.String(),
		model.ExecEventType.String(),
		model.ExitEventType.String(),
	}
)

// PlatformProbe defines a platform probe
type PlatformProbe struct {
	// Constants and configuration
	Manager        *manager.Manager
	managerOptions manager.Options
	kernelVersion  *kernel.Version

	// internals
	monitor         *Monitor
	profileManagers *SecurityProfileManagers

	// Ring
	eventStream EventStream

	// ActivityDumps section
	activityDumpHandler dump.ActivityDumpHandler

	// Approvers / discarders section
	Erpc                           *erpc.ERPC
	erpcRequest                    *erpc.Request
	inodeDiscarders                *inodeDiscarders
	notifyDiscarderPushedCallbacks []NotifyDiscarderPushedCallback
	approvers                      map[eval.EventType]kfilters.ActiveApprovers

	// Approvers / discarders section
	notifyDiscarderPushedCallbacksLock sync.Mutex

	isRuntimeDiscarded bool
	constantOffsets    map[string]uint64
	runtimeCompiled    bool

	useFentry bool
}

func (p *Probe) detectKernelVersion() error {
	kernelVersion, err := kernel.NewKernelVersion()
	if err != nil {
		return fmt.Errorf("unable to detect the kernel version: %w", err)
	}
	p.kernelVersion = kernelVersion
	return nil
}

// GetKernelVersion computes and returns the running kernel version
func (p *Probe) GetKernelVersion() (*kernel.Version, error) {
	if err := p.detectKernelVersion(); err != nil {
		return nil, err
	}
	return p.kernelVersion, nil
}

// UseRingBuffers returns true if eBPF ring buffers are supported and used
func (p *Probe) UseRingBuffers() bool {
	return p.Config.Probe.EventStreamUseRingBuffer && p.kernelVersion.HaveRingBuffers()
}

func (p *Probe) selectFentryMode() {
	if !p.Config.Probe.EventStreamUseFentry {
		p.useFentry = false
		return
	}

	supported := p.kernelVersion.HaveFentrySupport()
	if !supported {
		seclog.Errorf("fentry enabled but not supported, falling back to kprobe mode")
	}
	p.useFentry = supported
}

func (p *Probe) sanityChecks() error {
	// make sure debugfs is mounted
	if _, err := tracefs.Root(); err != nil {
		return err
	}

	if utilkernel.GetLockdownMode() == utilkernel.Confidentiality {
		return errors.New("eBPF not supported in lockdown `confidentiality` mode")
	}

	if p.Config.Probe.NetworkEnabled && p.kernelVersion.IsRH7Kernel() {
		seclog.Warnf("The network feature of CWS isn't supported on Centos7, setting runtime_security_config.network.enabled to false")
		p.Config.Probe.NetworkEnabled = false
	}

	return nil
}

// VerifyOSVersion returns an error if the current kernel version is not supported
func (p *Probe) VerifyOSVersion() error {
	if !p.kernelVersion.IsRH7Kernel() && !p.kernelVersion.IsRH8Kernel() && p.kernelVersion.Code < kernel.Kernel4_15 {
		return fmt.Errorf("the following kernel is not supported: %s", p.kernelVersion)
	}
	return nil
}

// VerifyEnvironment returns an error if the current environment seems to be misconfigured
func (p *Probe) VerifyEnvironment() *multierror.Error {
	var err *multierror.Error
	if aconfig.IsContainerized() {
		if mounted, _ := mountinfo.Mounted("/etc/passwd"); !mounted {
			err = multierror.Append(err, errors.New("/etc/passwd doesn't seem to be a mountpoint"))
		}

		if mounted, _ := mountinfo.Mounted("/etc/group"); !mounted {
			err = multierror.Append(err, errors.New("/etc/group doesn't seem to be a mountpoint"))
		}

		if mounted, _ := mountinfo.Mounted(utilkernel.ProcFSRoot()); !mounted {
			err = multierror.Append(err, errors.New("/etc/group doesn't seem to be a mountpoint"))
		}

		if mounted, _ := mountinfo.Mounted(p.kernelVersion.OsReleasePath); !mounted {
			err = multierror.Append(err, fmt.Errorf("%s doesn't seem to be a mountpoint", p.kernelVersion.OsReleasePath))
		}

		securityFSPath := filepath.Join(utilkernel.SysFSRoot(), "kernel/security")
		if mounted, _ := mountinfo.Mounted(securityFSPath); !mounted {
			err = multierror.Append(err, fmt.Errorf("%s doesn't seem to be a mountpoint", securityFSPath))
		}

		capsEffective, _, capErr := utils.CapEffCapEprm(utils.Getpid())
		if capErr != nil {
			err = multierror.Append(capErr, errors.New("failed to get process capabilities"))
		} else {
			requiredCaps := []string{
				"CAP_SYS_ADMIN",
				"CAP_SYS_RESOURCE",
				"CAP_SYS_PTRACE",
				"CAP_NET_ADMIN",
				"CAP_NET_BROADCAST",
				"CAP_NET_RAW",
				"CAP_IPC_LOCK",
				"CAP_CHOWN",
			}

			for _, requiredCap := range requiredCaps {
				capConst := model.KernelCapabilityConstants[requiredCap]
				if capsEffective&capConst == 0 {
					err = multierror.Append(err, fmt.Errorf("%s capability is missing", requiredCap))
				}
			}
		}
	}

	return err
}

// Init initializes the probe
func (p *Probe) Init() error {
	p.startTime = time.Now()

	useSyscallWrapper, err := ebpf.IsSyscallWrapperRequired()
	if err != nil {
		return err
	}

	loader := ebpf.NewProbeLoader(p.Config.Probe, useSyscallWrapper, p.UseRingBuffers(), p.useFentry, p.StatsdClient)
	defer loader.Close()

	bytecodeReader, runtimeCompiled, err := loader.Load()
	if err != nil {
		return err
	}
	defer bytecodeReader.Close()

	p.runtimeCompiled = runtimeCompiled

	if err := p.eventStream.Init(p.Manager, p.Config.Probe); err != nil {
		return err
	}

	if p.isRuntimeDiscarded {
		p.managerOptions.ConstantEditors = append(p.managerOptions.ConstantEditors, manager.ConstantEditor{
			Name:  "runtime_discarded",
			Value: uint64(1),
		})
	}

	p.managerOptions.ActivatedProbes = append(p.managerOptions.ActivatedProbes, probes.SnapshotSelectors(p.useFentry)...)

	if err := p.Manager.InitWithOptions(bytecodeReader, p.managerOptions); err != nil {
		return fmt.Errorf("failed to init manager: %w", err)
	}

	p.inodeDiscarders = newInodeDiscarders(p.Erpc, p.resolvers.DentryResolver)

	if err := p.resolvers.Start(p.ctx); err != nil {
		return err
	}

	err = p.monitor.Init()
	if err != nil {
		return err
	}

	p.profileManagers, err = NewSecurityProfileManagers(p)
	if err != nil {
		return err
	}
	p.profileManagers.AddActivityDumpHandler(p.activityDumpHandler)

	p.eventStream.SetMonitor(p.monitor.eventStreamMonitor)

	return nil
}

// IsRuntimeCompiled returns true if the eBPF programs where successfully runtime compiled
func (p *Probe) IsRuntimeCompiled() bool {
	return p.runtimeCompiled
}

// Setup the runtime security probe
func (p *Probe) Setup() error {
	if err := p.Manager.Start(); err != nil {
		return err
	}
	ebpfcheck.AddNameMappings(p.Manager, "cws")

	p.applyDefaultFilterPolicies()

	if err := p.updateProbes(defaultEventTypes, true); err != nil {
		return err
	}

	p.profileManagers.Start(p.ctx, &p.wg)

	return nil
}

// Start plays the snapshot data and then start the event stream
func (p *Probe) Start() error {
	// Apply rules to the snapshotted data before starting the event stream to avoid concurrency issues
	p.playSnapshot()
	return p.eventStream.Start(&p.wg)
}

// playSnapshot plays a snapshot
func (p *Probe) playSnapshot() {
	// Get the snapshotted data
	var events []*model.Event

	entryToEvent := func(entry *model.ProcessCacheEntry) {
		if entry.Source != model.ProcessCacheEntryFromSnapshot {
			return
		}
		entry.Retain()
		event := NewEvent(p.fieldHandlers)
		event.Type = uint32(model.ExecEventType)
		event.TimestampRaw = uint64(time.Now().UnixNano())
		event.ProcessCacheEntry = entry
		event.ProcessContext = &entry.ProcessContext
		event.Exec.Process = &entry.Process
		event.ProcessContext.Process.ContainerID = entry.ContainerID

		if _, err := entry.HasValidLineage(); err != nil {
			event.Error = &model.ErrProcessBrokenLineage{Err: err}
		}

		events = append(events, event)
	}
	p.GetResolvers().ProcessResolver.Walk(entryToEvent)
	for _, event := range events {
		p.DispatchEvent(event)
		event.ProcessCacheEntry.Release()
	}
}

func (p *Probe) sendAnomalyDetection(event *model.Event) {
	tags := p.GetEventTags(event.ContainerContext.ID)
	if service := p.GetService(event); service != "" {
		tags = append(tags, "service:"+service)
	}

	p.DispatchCustomEvent(
		events.NewCustomRule(events.AnomalyDetectionRuleID, events.AnomalyDetectionRuleDesc),
		events.NewCustomEventLazy(event.GetEventType(), p.EventMarshallerCtor(event), tags...),
	)
}

// AddActivityDumpHandler set the probe activity dump handler
func (p *Probe) AddActivityDumpHandler(handler dump.ActivityDumpHandler) {
	p.activityDumpHandler = handler
}

// DispatchEvent sends an event to the probe event handler
func (p *Probe) DispatchEvent(event *model.Event) {
	traceEvent("Dispatching event %s", func() ([]byte, model.EventType, error) {
		eventJSON, err := serializers.MarshalEvent(event, p.resolvers)
		return eventJSON, event.GetEventType(), err
	})

	// filter out event if already present on a profile
	if p.Config.RuntimeSecurity.SecurityProfileEnabled {
		p.profileManagers.securityProfileManager.LookupEventInProfiles(event)
	}

	// send event to wildcard handlers, like the CWS rule engine, first
	p.sendEventToWildcardHandlers(event)

	// send event to specific event handlers, like the event monitor consumers, subsequently
	p.sendEventToSpecificEventTypeHandlers(event)

	// handle anomaly detections
	if event.IsAnomalyDetectionEvent() {
		if event.IsKernelSpaceAnomalyDetectionEvent() {
			p.profileManagers.securityProfileManager.FillProfileContextFromContainerID(event.FieldHandlers.ResolveContainerID(event, event.ContainerContext), &event.SecurityProfileContext)
		}
		p.sendAnomalyDetection(event)
	} else if event.Error == nil {
		// Process event after evaluation because some monitors need the DentryResolver to have been called first.
		if p.profileManagers.activityDumpManager != nil {
			p.profileManagers.activityDumpManager.ProcessEvent(event)
		}
	}
	p.monitor.ProcessEvent(event)
}

func (p *Probe) sendEventToWildcardHandlers(event *model.Event) {
	for _, handler := range p.fullAccessEventHandlers[model.UnknownEventType] {
		handler.HandleEvent(event)
	}
}

func (p *Probe) sendEventToSpecificEventTypeHandlers(event *model.Event) {
	for _, handler := range p.eventHandlers[event.GetEventType()] {
		handler.HandleEvent(handler.Copy(event))
	}
}

// DispatchCustomEvent sends a custom event to the probe event handler
func (p *Probe) DispatchCustomEvent(rule *rules.Rule, event *events.CustomEvent) {
	traceEvent("Dispatching custom event %s", func() ([]byte, model.EventType, error) {
		eventJSON, err := serializers.MarshalCustomEvent(event)
		return eventJSON, event.GetEventType(), err
	})

	// send specific event
	if p.Config.RuntimeSecurity.CustomEventEnabled {
		// send wildcard first
		for _, handler := range p.customEventHandlers[model.UnknownEventType] {
			handler.HandleCustomEvent(rule, event)
		}

		// send specific event
		for _, handler := range p.customEventHandlers[event.GetEventType()] {
			handler.HandleCustomEvent(rule, event)
		}
	}
}

func traceEvent(fmt string, marshaller func() ([]byte, model.EventType, error)) {
	if !seclog.DefaultLogger.IsTracing() {
		return
	}

	eventJSON, eventType, err := marshaller()
	if err != nil {
		seclog.DefaultLogger.TraceTagf(eventType, fmt, err)
		return
	}

	seclog.DefaultLogger.TraceTagf(eventType, fmt, string(eventJSON))
}

// SendStats sends statistics about the probe to Datadog
func (p *Probe) SendStats() error {
	p.resolvers.TCResolver.SendTCProgramsStats(p.StatsdClient)

	if err := p.profileManagers.SendStats(); err != nil {
		return err
	}

	return p.monitor.SendStats()
}

// GetMonitor returns the monitor of the probe
func (p *Probe) GetMonitor() *Monitor {
	return p.monitor
}

// EventMarshallerCtor returns the event marshaller ctor
func (p *Probe) EventMarshallerCtor(event *model.Event) func() easyjson.Marshaler {
	return func() easyjson.Marshaler {
		return serializers.NewEventSerializer(event, p.resolvers)
	}
}

func (p *Probe) unmarshalContexts(data []byte, event *model.Event) (int, error) {
	read, err := model.UnmarshalBinary(data, &event.PIDContext, &event.SpanContext, event.ContainerContext)
	if err != nil {
		return 0, err
	}

	return read, nil
}

func eventWithNoProcessContext(eventType model.EventType) bool {
	return eventType == model.DNSEventType || eventType == model.LoadModuleEventType || eventType == model.UnloadModuleEventType
}

// UnmarshalProcessCacheEntry unmarshal a Process
func (p *Probe) UnmarshalProcessCacheEntry(ev *model.Event, data []byte) (int, error) {
	entry := p.resolvers.ProcessResolver.NewProcessCacheEntry(ev.PIDContext)
	ev.ProcessCacheEntry = entry

	n, err := entry.Process.UnmarshalBinary(data)
	if err != nil {
		return n, err
	}
	entry.Process.ContainerID = ev.ContainerContext.ID

	return n, nil
}

func (p *Probe) onEventLost(perfMapName string, perEvent map[string]uint64) {
	p.DispatchCustomEvent(
		NewEventLostWriteEvent(perfMapName, perEvent),
	)

	// snapshot traced cgroups if a CgroupTracing event was lost
	if p.IsActivityDumpEnabled() && perEvent[model.CgroupTracingEventType.String()] > 0 {
		p.profileManagers.SnapshotTracedCgroups()
	}
}

// setProcessContext set the process context, should return false if the event shouldn't be dispatched
func (p *Probe) setProcessContext(eventType model.EventType, event *model.Event) bool {
	entry, isResolved := p.fieldHandlers.ResolveProcessCacheEntry(event)
	event.ProcessCacheEntry = entry
	if event.ProcessCacheEntry == nil {
		panic("should always return a process cache entry")
	}

	// use ProcessCacheEntry process context as process context
	event.ProcessContext = &event.ProcessCacheEntry.ProcessContext
	if event.ProcessContext == nil {
		panic("should always return a process context")
	}

	if process.IsKThread(event.ProcessContext.PPid, event.ProcessContext.Pid) {
		return false
	}

	if !eventWithNoProcessContext(eventType) {
		if !isResolved {
			event.Error = &model.ErrNoProcessContext{Err: errors.New("process context not resolved")}
		} else if _, err := entry.HasValidLineage(); err != nil {
			event.Error = &model.ErrProcessBrokenLineage{Err: err}
			p.resolvers.ProcessResolver.CountBrokenLineage()
		}
	}

	// flush exited process
	p.resolvers.ProcessResolver.DequeueExited()

	return true
}

func (p *Probe) handleEvent(CPU int, data []byte) {
	offset := 0
	event := p.zeroEvent()

	dataLen := uint64(len(data))

	read, err := event.UnmarshalBinary(data)
	if err != nil {
		seclog.Errorf("failed to decode event: %s", err)
		return
	}
	offset += read

	eventType := event.GetEventType()
	if eventType > model.MaxKernelEventType {
		seclog.Errorf("unsupported event type %d", eventType)
		return
	}

	p.monitor.eventStreamMonitor.CountEvent(eventType, event.TimestampRaw, 1, dataLen, eventstream.EventStreamMap, CPU)

	// no need to dispatch events
	switch eventType {
	case model.MountReleasedEventType:
		if _, err = event.MountReleased.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode mount released event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}

		// Remove all dentry entries belonging to the mountID
		p.resolvers.DentryResolver.DelCacheEntries(event.MountReleased.MountID)

		// Delete new mount point from cache
		if err = p.resolvers.MountResolver.Delete(event.MountReleased.MountID); err != nil {
			seclog.Tracef("failed to delete mount point %d from cache: %s", event.MountReleased.MountID, err)
		}
		return
	case model.ArgsEnvsEventType:
		if _, err = event.ArgsEnvs.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode args envs event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}

		p.resolvers.ProcessResolver.UpdateArgsEnvs(&event.ArgsEnvs)

		return
	case model.CgroupTracingEventType:
		if !p.Config.RuntimeSecurity.ActivityDumpEnabled {
			seclog.Errorf("shouldn't receive Cgroup event if activity dumps are disabled")
			return
		}

		if _, err = event.CgroupTracing.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode cgroup tracing event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}

		p.profileManagers.activityDumpManager.HandleCGroupTracingEvent(&event.CgroupTracing)
		return
	case model.UnshareMountNsEventType:
		if _, err = event.UnshareMountNS.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode unshare mnt ns event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
		if err := p.handleNewMount(event, &event.UnshareMountNS.Mount); err != nil {
			seclog.Debugf("failed to handle new mount from unshare mnt ns event: %s", err)
		}
		return
	}

	read, err = p.unmarshalContexts(data[offset:], event)
	if err != nil {
		seclog.Errorf("failed to decode event `%s`: %s", eventType, err)
		return
	}
	offset += read

	// save netns handle if applicable
	nsPath := utils.NetNSPathFromPid(event.PIDContext.Pid)
	_, _ = p.resolvers.NamespaceResolver.SaveNetworkNamespaceHandle(event.PIDContext.NetNS, nsPath)

	if model.GetEventTypeCategory(eventType.String()) == model.NetworkCategory {
		if read, err = event.NetworkContext.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode Network Context")
		}
		offset += read
	}

	// handle exec and fork before process context resolution as they modify the process context resolution
	switch eventType {
	case model.ForkEventType:
		if _, err = p.UnmarshalProcessCacheEntry(event, data[offset:]); err != nil {
			seclog.Errorf("failed to decode fork event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}

		if process.IsKThread(event.ProcessCacheEntry.PPid, event.ProcessCacheEntry.Pid) {
			return
		}

		p.resolvers.ProcessResolver.ApplyBootTime(event.ProcessCacheEntry)
		event.ProcessCacheEntry.SetSpan(event.SpanContext.SpanID, event.SpanContext.TraceID)

		p.resolvers.ProcessResolver.AddForkEntry(event.ProcessCacheEntry, event.PIDContext.ExecInode)
	case model.ExecEventType:
		// unmarshal and fill event.processCacheEntry
		if _, err = p.UnmarshalProcessCacheEntry(event, data[offset:]); err != nil {
			seclog.Errorf("failed to decode exec event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}

		if err = p.resolvers.ProcessResolver.ResolveNewProcessCacheEntry(event.ProcessCacheEntry, event.ContainerContext); err != nil {
			seclog.Debugf("failed to resolve new process cache entry context for pid %d: %s", event.PIDContext.Pid, err)

			var errResolution *path.ErrPathResolution
			if errors.As(err, &errResolution) {
				event.SetPathResolutionError(&event.ProcessCacheEntry.FileEvent, err)
			}
		} else {
			p.resolvers.ProcessResolver.AddExecEntry(event.ProcessCacheEntry, event.PIDContext.ExecInode)
		}

		event.Exec.Process = &event.ProcessCacheEntry.Process
	}

	if !p.setProcessContext(eventType, event) {
		return
	}

	switch eventType {
	case model.FileMountEventType:
		if _, err = event.Mount.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode mount event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
		if err := p.handleNewMount(event, &event.Mount.Mount); err != nil {
			seclog.Debugf("failed to handle new mount from mount event: %s\n", err)
			return
		}

		// TODO: this should be moved in the resolver itself in order to handle the fallbacks
		if event.Mount.GetFSType() == "nsfs" {
			nsid := uint32(event.Mount.RootPathKey.Inode)
			mountPath, err := p.resolvers.MountResolver.ResolveMountPath(event.Mount.MountID, event.Mount.Device, event.PIDContext.Pid, event.ContainerContext.ID)
			if err != nil {
				seclog.Debugf("failed to get mount path: %v", err)
			} else {
				mountNetNSPath := utils.NetNSPathFromPath(mountPath)
				_, _ = p.resolvers.NamespaceResolver.SaveNetworkNamespaceHandle(nsid, mountNetNSPath)
			}
		}

	case model.FileUmountEventType:
		if _, err = event.Umount.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode umount event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}

		// we can skip this error as this is for the umount only and there is no impact on the filepath resolution
		mount, _ := p.resolvers.MountResolver.ResolveMount(event.Umount.MountID, 0, event.PIDContext.Pid, event.ContainerContext.ID)
		if mount != nil && mount.GetFSType() == "nsfs" {
			nsid := uint32(mount.RootPathKey.Inode)
			if namespace := p.resolvers.NamespaceResolver.ResolveNetworkNamespace(nsid); namespace != nil {
				p.FlushNetworkNamespace(namespace)
			}
		}

	case model.FileOpenEventType:
		if _, err = event.Open.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode open event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileMkdirEventType:
		if _, err = event.Mkdir.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode mkdir event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileRmdirEventType:
		if _, err = event.Rmdir.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode rmdir event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileUnlinkEventType:
		if _, err = event.Unlink.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode unlink event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileRenameEventType:
		if _, err = event.Rename.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode rename event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileChmodEventType:
		if _, err = event.Chmod.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode chmod event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileChownEventType:
		if _, err = event.Chown.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode chown event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileUtimesEventType:
		if _, err = event.Utimes.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode utime event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileLinkEventType:
		if _, err = event.Link.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode link event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileSetXAttrEventType:
		if _, err = event.SetXAttr.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode setxattr event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.FileRemoveXAttrEventType:
		if _, err = event.RemoveXAttr.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode removexattr event: %s (offset %d, len %d)", err, offset, dataLen)
			return
		}
	case model.ExitEventType:
		if _, err = event.Exit.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode exit event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}

		var exists bool
		event.ProcessCacheEntry, exists = p.fieldHandlers.GetProcessCacheEntry(event)
		if !exists {
			// no need to dispatch an exit event that don't have the corresponding cache entry
			return
		}

		// Use the event timestamp as exit time
		// The local process cache hasn't been updated yet with the exit time when the exit event is first seen
		// The pid_cache kernel map has the exit_time but it's only accessed if there's a local miss
		event.ProcessCacheEntry.Process.ExitTime = p.fieldHandlers.ResolveEventTime(event)
		event.Exit.Process = &event.ProcessCacheEntry.Process

		// update mount pid mapping
		p.resolvers.MountResolver.DelPid(event.Exit.Pid)
	case model.SetuidEventType:
		// the process context may be incorrect, do not modify it
		if event.Error != nil {
			break
		}

		if _, err = event.SetUID.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode setuid event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		defer p.resolvers.ProcessResolver.UpdateUID(event.PIDContext.Pid, event)
	case model.SetgidEventType:
		// the process context may be incorrect, do not modify it
		if event.Error != nil {
			break
		}

		if _, err = event.SetGID.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode setgid event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		defer p.resolvers.ProcessResolver.UpdateGID(event.PIDContext.Pid, event)
	case model.CapsetEventType:
		// the process context may be incorrect, do not modify it
		if event.Error != nil {
			break
		}

		if _, err = event.Capset.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode capset event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		defer p.resolvers.ProcessResolver.UpdateCapset(event.PIDContext.Pid, event)
	case model.SELinuxEventType:
		if _, err = event.SELinux.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode selinux event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	case model.BPFEventType:
		if _, err = event.BPF.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode bpf event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	case model.PTraceEventType:
		if _, err = event.PTrace.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode ptrace event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		// resolve tracee process context
		var pce *model.ProcessCacheEntry
		if event.PTrace.PID > 0 { // pid can be 0 for a PTRACE_TRACEME request
			pce = p.resolvers.ProcessResolver.Resolve(event.PTrace.PID, event.PTrace.PID, 0, false)
		}
		if pce == nil {
			pce = model.NewPlaceholderProcessCacheEntry(event.PTrace.PID, event.PTrace.PID, false)
		}
		event.PTrace.Tracee = &pce.ProcessContext
	case model.MMapEventType:
		if _, err = event.MMap.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode mmap event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}

		if event.MMap.Flags&unix.MAP_ANONYMOUS != 0 {
			// no need to trigger a dentry resolver, not backed by any file
			event.MMap.File.SetPathnameStr("")
			event.MMap.File.SetBasenameStr("")
		}
	case model.MProtectEventType:
		if _, err = event.MProtect.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode mprotect event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	case model.LoadModuleEventType:
		if _, err = event.LoadModule.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode load_module event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}

		if event.LoadModule.LoadedFromMemory {
			// no need to trigger a dentry resolver, not backed by any file
			event.LoadModule.File.SetPathnameStr("")
			event.LoadModule.File.SetBasenameStr("")
		}
	case model.UnloadModuleEventType:
		if _, err = event.UnloadModule.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode unload_module event: %s (offset %d, len %d)", err, offset, len(data))
		}
	case model.SignalEventType:
		if _, err = event.Signal.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode signal event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		// resolve target process context
		var pce *model.ProcessCacheEntry
		if event.Signal.PID > 0 { // Linux accepts a kill syscall with both negative and zero pid
			pce = p.resolvers.ProcessResolver.Resolve(event.Signal.PID, event.Signal.PID, 0, false)
		}
		if pce == nil {
			pce = model.NewPlaceholderProcessCacheEntry(event.Signal.PID, event.Signal.PID, false)
		}
		event.Signal.Target = &pce.ProcessContext
	case model.SpliceEventType:
		if _, err = event.Splice.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode splice event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	case model.NetDeviceEventType:
		if _, err = event.NetDevice.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode net_device event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		_ = p.setupNewTCClassifier(event.NetDevice.Device)
	case model.VethPairEventType:
		if _, err = event.VethPair.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode veth_pair event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
		_ = p.setupNewTCClassifier(event.VethPair.PeerDevice)
	case model.DNSEventType:
		if _, err = event.DNS.UnmarshalBinary(data[offset:]); err != nil {
			if errors.Is(err, model.ErrDNSNameMalformatted) {
				seclog.Debugf("failed to validate DNS event: %s", event.DNS.Name)
			} else if errors.Is(err, model.ErrDNSNamePointerNotSupported) {
				seclog.Tracef("failed to decode DNS event: %s (offset %d, len %d)", err, offset, len(data))
			} else {
				seclog.Errorf("failed to decode DNS event: %s (offset %d, len %d)", err, offset, len(data))
			}

			return
		}
	case model.BindEventType:
		if _, err = event.Bind.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode bind event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	case model.SyscallsEventType:
		if _, err = event.Syscalls.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode syscalls event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	case model.AnomalyDetectionSyscallEventType:
		if _, err = event.AnomalyDetectionSyscallEvent.UnmarshalBinary(data[offset:]); err != nil {
			seclog.Errorf("failed to decode anomaly detection for syscall event: %s (offset %d, len %d)", err, offset, len(data))
			return
		}
	}

	// resolve the container context
	event.ContainerContext, _ = p.fieldHandlers.ResolveContainerContext(event)

	p.DispatchEvent(event)

	if eventType == model.ExitEventType {
		p.resolvers.ProcessResolver.DeleteEntry(event.ProcessContext.Pid, p.fieldHandlers.ResolveEventTime(event))
	}
}

// AddNewNotifyDiscarderPushedCallback add a callback to the list of func that have to be called when a discarder is pushed to kernel
func (p *Probe) AddNewNotifyDiscarderPushedCallback(cb NotifyDiscarderPushedCallback) {
	p.notifyDiscarderPushedCallbacksLock.Lock()
	defer p.notifyDiscarderPushedCallbacksLock.Unlock()

	p.notifyDiscarderPushedCallbacks = append(p.notifyDiscarderPushedCallbacks, cb)
}

// OnNewDiscarder is called when a new discarder is found
func (p *Probe) OnNewDiscarder(rs *rules.RuleSet, ev *model.Event, field eval.Field, eventType eval.EventType) {
	// discarders disabled
	if !p.Config.Probe.EnableDiscarders {
		return
	}

	if p.isRuntimeDiscarded {
		fakeTime := time.Unix(0, int64(ev.TimestampRaw))
		if !p.discarderRateLimiter.AllowN(fakeTime, 1) {
			return
		}
	}

	seclog.Tracef("New discarder of type %s for field %s", eventType, field)

	if handlers, ok := allDiscarderHandlers[eventType]; ok {
		for _, handler := range handlers {
			discarderPushed, _ := handler(rs, ev, p, Discarder{Field: field})

			if discarderPushed {
				p.notifyDiscarderPushedCallbacksLock.Lock()
				defer p.notifyDiscarderPushedCallbacksLock.Unlock()
				for _, cb := range p.notifyDiscarderPushedCallbacks {
					cb(eventType, ev, field)
				}
			}
		}
	}
}

// ApplyFilterPolicy is called when a passing policy for an event type is applied
func (p *Probe) ApplyFilterPolicy(eventType eval.EventType, mode kfilters.PolicyMode, flags kfilters.PolicyFlag) error {
	seclog.Infof("Setting in-kernel filter policy to `%s` for `%s`", mode, eventType)
	table, err := managerhelper.Map(p.Manager, "filter_policy")
	if err != nil {
		return fmt.Errorf("unable to find policy table: %w", err)
	}

	et := config.ParseEvalEventType(eventType)
	if et == model.UnknownEventType {
		return errors.New("unable to parse the eval event type")
	}

	policy := &kfilters.FilterPolicy{
		Mode:  mode,
		Flags: flags,
	}

	return table.Put(ebpf.Uint32MapItem(et), policy)
}

// SetApprovers applies approvers and removes the unused ones
func (p *Probe) SetApprovers(eventType eval.EventType, approvers rules.Approvers) error {
	handler, exists := kfilters.AllApproversHandlers[eventType]
	if !exists {
		return nil
	}

	newApprovers, err := handler(approvers)
	if err != nil {
		seclog.Errorf("Error while adding approvers fallback in-kernel policy to `%s` for `%s`: %s", kfilters.PolicyModeAccept, eventType, err)
	}

	type tag struct {
		eventType    eval.EventType
		approverType string
	}
	approverAddedMetricCounter := make(map[tag]float64)

	for _, newApprover := range newApprovers {
		seclog.Tracef("Applying approver %+v for event type %s", newApprover, eventType)
		if err := newApprover.Apply(p.Manager); err != nil {
			return err
		}

		approverType := getApproverType(newApprover.GetTableName())
		approverAddedMetricCounter[tag{eventType, approverType}]++
	}

	if previousApprovers, exist := p.approvers[eventType]; exist {
		previousApprovers.Sub(newApprovers)
		for _, previousApprover := range previousApprovers {
			seclog.Tracef("Removing previous approver %+v for event type %s", previousApprover, eventType)
			if err := previousApprover.Remove(p.Manager); err != nil {
				return err
			}

			approverType := getApproverType(previousApprover.GetTableName())
			approverAddedMetricCounter[tag{eventType, approverType}]--
			if approverAddedMetricCounter[tag{eventType, approverType}] <= 0 {
				delete(approverAddedMetricCounter, tag{eventType, approverType})
			}
		}
	}

	for tags, count := range approverAddedMetricCounter {
		tags := []string{
			fmt.Sprintf("approver_type:%s", tags.approverType),
			fmt.Sprintf("event_type:%s", tags.eventType),
		}

		if err := p.StatsdClient.Gauge(metrics.MetricApproverAdded, count, tags, 1.0); err != nil {
			seclog.Tracef("couldn't set MetricApproverAdded metric: %s", err)
		}
	}

	p.approvers[eventType] = newApprovers
	return nil
}

func getApproverType(approverTableName string) string {
	approverType := "flag"

	if approverTableName == kfilters.BasenameApproverKernelMapName {
		approverType = "basename"
	}

	return approverType
}

func (p *Probe) isNeededForActivityDump(eventType eval.EventType) bool {
	if p.Config.RuntimeSecurity.ActivityDumpEnabled {
		for _, e := range p.profileManagers.GetActivityDumpTracedEventTypes() {
			if e.String() == eventType {
				return true
			}
		}
	}
	return false
}

func (p *Probe) isNeededForSecurityProfile(eventType eval.EventType) bool {
	if p.Config.RuntimeSecurity.SecurityProfileEnabled {
		for _, e := range p.Config.RuntimeSecurity.AnomalyDetectionEventTypes {
			if e.String() == eventType {
				return true
			}
		}
	}
	return false
}

func (p *Probe) validEventTypeForConfig(eventType string) bool {
	if eventType == "dns" && !p.Config.Probe.NetworkEnabled {
		return false
	}
	return true
}

// updateProbes applies the loaded set of rules and returns a report
// of the applied approvers for it.
func (p *Probe) updateProbes(ruleEventTypes []eval.EventType, useSnapshotProbes bool) error {
	// event types enabled either by event handlers or by rules
	eventTypes := append([]eval.EventType{}, defaultEventTypes...)
	eventTypes = append(eventTypes, ruleEventTypes...)
	for eventType, handlers := range p.eventHandlers {
		if len(handlers) == 0 {
			continue
		}
		if slices.Contains(eventTypes, model.EventType(eventType).String()) {
			continue
		}
		if eventType != int(model.UnknownEventType) && eventType != int(model.MaxAllEventType) {
			eventTypes = append(eventTypes, model.EventType(eventType).String())
		}
	}

	var activatedProbes []manager.ProbesSelector

	if useSnapshotProbes {
		activatedProbes = append(activatedProbes, probes.SnapshotSelectors(p.useFentry)...)
	}

	// extract probe to activate per the event types
	for eventType, selectors := range probes.GetSelectorsPerEventType(p.useFentry) {
		if (eventType == "*" || slices.Contains(eventTypes, eventType) || p.isNeededForActivityDump(eventType) || p.isNeededForSecurityProfile(eventType)) && p.validEventTypeForConfig(eventType) {
			activatedProbes = append(activatedProbes, selectors...)
		}
	}

	activatedProbes = append(activatedProbes, p.resolvers.TCResolver.SelectTCProbes())

	// ActivityDumps
	if p.Config.RuntimeSecurity.ActivityDumpEnabled {
		for _, e := range p.profileManagers.GetActivityDumpTracedEventTypes() {
			if e == model.SyscallsEventType {
				activatedProbes = append(activatedProbes, probes.SyscallMonitorSelectors...)
				break
			}
		}
	}

	// Print the list of unique probe identification IDs that are registered
	var selectedIDs []manager.ProbeIdentificationPair
	for _, selector := range activatedProbes {
		for _, id := range selector.GetProbesIdentificationPairList() {
			var exists bool
			for _, selectedID := range selectedIDs {
				if selectedID == id {
					exists = true
				}
			}
			if !exists {
				selectedIDs = append(selectedIDs, id)
				seclog.Tracef("probe %s selected", id)
			}
		}
	}

	enabledEventsMap, err := managerhelper.Map(p.Manager, "enabled_events")
	if err != nil {
		return err
	}

	enabledEvents := uint64(0)
	for _, eventName := range eventTypes {
		if eventName != "*" {
			eventType := config.ParseEvalEventType(eventName)
			if eventType == model.UnknownEventType {
				return fmt.Errorf("unknown event type '%s'", eventName)
			}
			enabledEvents |= 1 << (eventType - 1)
		}
	}

	if err := enabledEventsMap.Put(ebpf.ZeroUint32MapItem, enabledEvents); err != nil {
		return fmt.Errorf("failed to set enabled events: %w", err)
	}

	return p.Manager.UpdateActivatedProbes(activatedProbes)
}

// GetDiscarders retrieve the discarders
func (p *Probe) GetDiscarders() (*DiscardersDump, error) {
	inodeMap, err := managerhelper.Map(p.Manager, "inode_discarders")
	if err != nil {
		return nil, err
	}

	pidMap, err := managerhelper.Map(p.Manager, "pid_discarders")
	if err != nil {
		return nil, err
	}

	statsFB, err := managerhelper.Map(p.Manager, "fb_discarder_stats")
	if err != nil {
		return nil, err
	}

	statsBB, err := managerhelper.Map(p.Manager, "bb_discarder_stats")
	if err != nil {
		return nil, err
	}

	dump, err := dumpDiscarders(p.resolvers.DentryResolver, pidMap, inodeMap, statsFB, statsBB)
	if err != nil {
		return nil, err
	}
	return &dump, nil
}

// DumpDiscarders removes all the discarders
func (p *Probe) DumpDiscarders() (string, error) {
	seclog.Debugf("Dumping discarders")

	dump, err := p.GetDiscarders()
	if err != nil {
		return "", err
	}

	fp, err := os.CreateTemp("/tmp", "discarder-dump-")
	if err != nil {
		return "", err
	}
	defer fp.Close()

	if err := os.Chmod(fp.Name(), 0400); err != nil {
		return "", err
	}

	encoder := yaml.NewEncoder(fp)
	defer encoder.Close()

	if err := encoder.Encode(dump); err != nil {
		return "", err
	}
	err = fp.Close()
	if err != nil {
		return "", fmt.Errorf("could not close file [%s]: %w", fp.Name(), err)
	}
	return fp.Name(), err
}

// FlushDiscarders invalidates all the discarders
func (p *Probe) FlushDiscarders() error {
	seclog.Debugf("Flushing discarders")
	return bumpDiscardersRevision(p.Erpc)
}

// RefreshUserCache refreshes the user cache
func (p *Probe) RefreshUserCache(containerID string) error {
	return p.GetResolvers().UserGroupResolver.RefreshCache(containerID)
}

// Snapshot runs the different snapshot functions of the resolvers that
// require to sync with the current state of the system
func (p *Probe) Snapshot() error {
	// the snapshot for the read of a lot of file which can allocate a lot of memory.
	defer runtime.GC()
	return p.resolvers.Snapshot()
}

// Stop the probe
func (p *Probe) Stop() {
	_ = p.Manager.StopReaders(manager.CleanAll)
}

// Close the probe
func (p *Probe) Close() error {
	// Cancelling the context will stop the reorderer = we won't dequeue events anymore and new events from the
	// perf map reader are ignored
	p.cancelFnc()

	// we wait until both the reorderer and the monitor are stopped
	p.wg.Wait()

	ebpfcheck.RemoveNameMappings(p.Manager)
	// Stopping the manager will stop the perf map reader and unload eBPF programs
	if err := p.Manager.Stop(manager.CleanAll); err != nil {
		return err
	}

	// when we reach this point, we do not generate nor consume events anymore, we can close the resolvers
	return p.resolvers.Close()
}

// GetDebugStats returns the debug stats
func (p *Probe) GetDebugStats() map[string]interface{} {
	debug := map[string]interface{}{
		"start_time": p.startTime.String(),
	}
	// TODO(Will): add manager state
	return debug
}

// QueuedNetworkDeviceError is used to indicate that the new network device was queued until its namespace handle is
// resolved.
type QueuedNetworkDeviceError struct {
	msg string
}

func (err QueuedNetworkDeviceError) Error() string {
	return err.msg
}

func (p *Probe) setupNewTCClassifier(device model.NetDevice) error {
	// select netns handle
	var handle *os.File
	var err error
	netns := p.resolvers.NamespaceResolver.ResolveNetworkNamespace(device.NetNS)
	if netns != nil {
		handle, err = netns.GetNamespaceHandleDup()
	}
	if err != nil {
		defer handle.Close()
	}
	if netns == nil || err != nil || handle == nil {
		// queue network device so that a TC classifier can be added later
		p.resolvers.NamespaceResolver.QueueNetworkDevice(device)
		return QueuedNetworkDeviceError{msg: fmt.Sprintf("device %s is queued until %d is resolved", device.Name, device.NetNS)}
	}
	err = p.resolvers.TCResolver.SetupNewTCClassifierWithNetNSHandle(device, handle, p.Manager)
	if err != nil {
		return err
	}
	if handle != nil {
		if err := handle.Close(); err != nil {
			return fmt.Errorf("could not close file [%s]: %w", handle.Name(), err)
		}
	}
	return err
}

// FlushNetworkNamespace removes all references and stops all TC programs in the provided network namespace. This method
// flushes the network namespace in the network namespace resolver as well.
func (p *Probe) FlushNetworkNamespace(namespace *netns.NetworkNamespace) {
	p.resolvers.NamespaceResolver.FlushNetworkNamespace(namespace)

	// cleanup internal structures
	p.resolvers.TCResolver.FlushNetworkNamespaceID(namespace.ID(), p.Manager)
}

func (p *Probe) handleNewMount(ev *model.Event, m *model.Mount) error {
	// There could be entries of a previous mount_id in the cache for instance,
	// runc does the following : it bind mounts itself (using /proc/exe/self),
	// opens a file descriptor on the new file with O_CLOEXEC then umount the bind mount using
	// MNT_DETACH. It then does an exec syscall, that will cause the fd to be closed.
	// Our dentry resolution of the exec event causes the inode/mount_id to be put in cache,
	// so we remove all dentry entries belonging to the mountID.
	p.resolvers.DentryResolver.DelCacheEntries(m.MountID)

	// Resolve mount point
	if err := p.resolvers.PathResolver.SetMountPoint(ev, m); err != nil {
		seclog.Debugf("failed to set mount point: %v", err)
		return err
	}
	// Resolve root
	if err := p.resolvers.PathResolver.SetMountRoot(ev, m); err != nil {
		seclog.Debugf("failed to set mount root: %v", err)
		return err
	}

	// Insert new mount point in cache, passing it a copy of the mount that we got from the event
	if err := p.resolvers.MountResolver.Insert(*m, 0); err != nil {
		seclog.Errorf("failed to insert mount event: %v", err)
		return err
	}

	return nil
}

func (p *Probe) applyDefaultFilterPolicies() {
	if !p.Config.Probe.EnableKernelFilters {
		seclog.Warnf("Forcing in-kernel filter policy to `pass`: filtering not enabled")
	}

	for eventType := model.FirstEventType; eventType <= model.LastEventType; eventType++ {
		var mode kfilters.PolicyMode

		if !p.Config.Probe.EnableKernelFilters {
			mode = kfilters.PolicyModeNoFilter
		} else if len(p.eventHandlers[eventType]) > 0 {
			mode = kfilters.PolicyModeAccept
		} else {
			mode = kfilters.PolicyModeDeny
		}

		if err := p.ApplyFilterPolicy(eventType.String(), mode, math.MaxUint8); err != nil {
			seclog.Debugf("unable to apply to filter policy `%s` for `%s`", eventType, mode)
		}
	}
}

// ApplyRuleSet setup the probes for the provided set of rules and returns the policy report.
func (p *Probe) ApplyRuleSet(rs *rules.RuleSet) (*kfilters.ApplyRuleSetReport, error) {
	ars, err := kfilters.NewApplyRuleSetReport(p.Config.Probe, rs)
	if err != nil {
		return nil, err
	}

	for eventType, report := range ars.Policies {
		if err := p.ApplyFilterPolicy(eventType, report.Mode, report.Flags); err != nil {
			return nil, err
		}
		if err := p.SetApprovers(eventType, report.Approvers); err != nil {
			return nil, err
		}
	}

	if err := p.updateProbes(rs.GetEventTypes(), false); err != nil {
		return nil, fmt.Errorf("failed to select probes: %w", err)
	}

	return ars, nil
}

// NewProbe instantiates a new runtime security agent probe
func NewProbe(config *config.Config, opts Opts) (*Probe, error) {
	opts.normalize()

	p := &Probe{
		Opts:         opts,
		Config:       config,
		StatsdClient: opts.StatsdClient,
		scrubber:     newProcScrubber(config.Probe.CustomSensitiveWords),
	}

	if opts.EBPFLessEnabled {
		pp, err := NewEBPFLessProbe(p, config, opts)
		if err != nil {
			return nil, err
		}
		p.PlatformProbe = pp
	} else {
		pp, err := NewEBPFProbe(p, config, opts)
		if err != nil {
			return nil, err
		}
		p.PlatformProbe = pp
	}

	return p, nil
}
