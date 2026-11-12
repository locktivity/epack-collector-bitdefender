package collector

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// The normalized artifact's schema ID, its path in the pack, and the fixed
// values it holds.
const (
	normalizedSchema        = "evidencepack/endpoint-posture@v1"
	normalizedSchemaVersion = "1.0.0"
	normalizedProvider      = "bitdefender"
	scopeDescription        = "gravityzone_computers"
	// maxObservationAge is what scope.max_observation_age_seconds holds.
	// Every computer counts however long ago it last synced with Control
	// Center, so the age is set far past any real one.
	maxObservationAge = 10 * 365 * 24 * time.Hour
)

var normalizedPath = componentsdk.ArtifactPath(collectorName, normalizedSchema)

// Normalized is the evidencepack/endpoint-posture@v1 artifact. A nil pointer
// marks a value that was not read. The counts, the coverage, and the device
// rows are written from the audit level, as the schema marks them.
type Normalized struct {
	SchemaVersion  string                    `json:"schema_version"`
	CollectedAt    string                    `json:"collected_at"`
	Provider       string                    `json:"provider"`
	Scope          NormalizedScope           `json:"scope"`
	Fleet          *NormalizedFleet          `json:"fleet,omitempty"`
	Protection     *NormalizedProtection     `json:"protection,omitempty"`
	MetricCoverage map[string]MetricCoverage `json:"metric_coverage,omitempty"`
	Availability   []Availability            `json:"availability"`
	Devices        *[]Device                 `json:"devices,omitempty"`
}

// NormalizedScope says which devices the artifact covers.
type NormalizedScope struct {
	// DiscoveryComplete is nil when a failed call leaves it unknown.
	DiscoveryComplete        *bool  `json:"discovery_complete"`
	ObservedDeviceCount      *int   `json:"observed_device_count,omitempty"`
	Description              string `json:"description"`
	MaxObservationAgeSeconds int64  `json:"max_observation_age_seconds"`
}

// NormalizedFleet holds the totals over the computers. It is left out when
// discovery is incomplete, because the computers read are not the fleet.
type NormalizedFleet struct {
	DevicesPresent     *bool          `json:"devices_present,omitempty"`
	DeviceCount        *int           `json:"device_count,omitempty"`
	ManagedDeviceCount *int           `json:"managed_device_count,omitempty"`
	DevicesByOS        map[string]int `json:"devices_by_os,omitempty"`
}

// NormalizedProtection holds the antimalware and EDR percentages.
type NormalizedProtection struct {
	AntimalwareInstalledPct Percentage `json:"antimalware_installed_pct,omitzero"`
	AntimalwareHealthyPct   Percentage `json:"antimalware_healthy_pct,omitzero"`
	EDRInstalledPct         Percentage `json:"edr_installed_pct,omitzero"`
}

// MetricCoverage counts the computers behind one percentage by outcome. The
// percentage is passing over passing and failing.
type MetricCoverage struct {
	Passing       int `json:"passing_device_count"`
	Failing       int `json:"failing_device_count"`
	Unknown       int `json:"unknown_device_count"`
	NotApplicable int `json:"not_applicable_device_count"`
}

// Availability records why a metric has no reading.
type Availability struct {
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

// Device is one computer's row.
type Device struct {
	DeviceID          string                   `json:"device_id"`
	Hostname          string                   `json:"hostname,omitempty"`
	OSFamily          string                   `json:"os_family"`
	OSName            string                   `json:"os_name,omitempty"`
	ManagementState   string                   `json:"management_state"`
	InScope           bool                     `json:"in_scope"`
	LastSeenAt        string                   `json:"last_seen_at,omitempty"`
	Controls          map[string]DeviceControl `json:"controls,omitempty"`
	ProtectionModules *[]ProtectionModule      `json:"protection_modules,omitempty"`
}

// DeviceControl is one computer's reading for one control.
type DeviceControl struct {
	State string `json:"state"`
}

// ProtectionModule is one GravityZone module on a computer.
type ProtectionModule struct {
	Kind    string `json:"kind"`
	Enabled *bool  `json:"enabled,omitempty"`
	Healthy *bool  `json:"healthy,omitempty"`
}

// Percentage is a normalized percentage. It is left out when Read is false.
// Otherwise it is written as Value, which is nil over an empty population.
type Percentage struct {
	Value *float64
	Read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p Percentage) IsZero() bool { return !p.Read }

// MarshalJSON writes the value, or null.
func (p Percentage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Value) }

func percentOf(passing, evaluated int) Percentage {
	pct := componentsdk.Percent(passing, evaluated, componentsdk.RoundDown)
	if pct == nil {
		return Percentage{Read: true}
	}
	v := float64(*pct)
	return Percentage{Value: &v, Read: true}
}

// Control states, as the schema names them.
const (
	statePass    = "pass"
	stateFail    = "fail"
	stateUnknown = "unknown"
)

// Availability reasons, as the schema names them.
const (
	reasonUnsupported      = "unsupported"
	reasonPermissionDenied = "permission_denied"
	reasonNotRead          = "not_read"
	reasonPartial          = "partial"
	reasonSourceError      = "source_error"
)

// availabilityReason is the availability reason for a value with no
// reading. It matches the value's gap code. A not_read value's message
// includes where GravityZone reports it.
func availabilityReason(code componentsdk.Code) string {
	if code == componentsdk.CodeNotRead {
		return reasonNotRead
	}
	return reasonUnsupported
}

// protectionMetric is one percentage the collector measures.
type protectionMetric struct {
	path    string // the metric_coverage key and availability path
	pointer string
	control string // the device row's control key
}

var protectionMetrics = []protectionMetric{
	{"protection.antimalware_installed_pct", "/protection/antimalware_installed_pct", "antimalware_installed"},
	{"protection.antimalware_healthy_pct", "/protection/antimalware_healthy_pct", "antimalware_healthy"},
	{"protection.edr_installed_pct", "/protection/edr_installed_pct", "edr_installed"},
}

// unreadValue is a value the collector has no reading for. Its code is
// unsupported when GravityZone's API does not report it, and not_read when
// the API reports it in a call the collector does not make.
type unreadValue struct {
	pointer string
	// path is the availability path, or "" for a count the availability
	// list does not name.
	path   string
	audit  bool
	code   componentsdk.Code
	reason string
}

var unreadValues = []unreadValue{
	{"/compliance/compliant_pct", "compliance.compliant_pct", false, componentsdk.CodeUnsupported, "GravityZone's API does not report a compliance verdict for a computer."},
	{"/fleet/mdm_enrolled_pct", "fleet.mdm_enrolled_pct", false, componentsdk.CodeUnsupported, "GravityZone does not enroll computers in mobile device management."},
	{"/fleet/mdm_enrolled_device_count", "", true, componentsdk.CodeUnsupported, "GravityZone does not enroll computers in mobile device management."},
	{"/hardening/disk_encryption_pct", "hardening.disk_encryption_pct", false, componentsdk.CodeNotRead, "GravityZone's Endpoint Encryption Status report from the Reports API gives each volume's encryption status, which this collector does not read."},
	{"/hardening/firewall_enabled_pct", "hardening.firewall_enabled_pct", false, componentsdk.CodeUnsupported, "GravityZone reports only its own firewall module, so a computer that uses the operating system's firewall would read as off."},
	{"/hardening/screen_lock_compliant_pct", "hardening.screen_lock_compliant_pct", false, componentsdk.CodeUnsupported, "GravityZone's API does not report a computer's screen lock setting."},
	{"/patching/os_supported_pct", "patching.os_supported_pct", false, componentsdk.CodeUnsupported, "GravityZone does not report whether a computer's operating system version still gets security updates."},
	{"/patching/os_baseline_compliant_pct", "patching.os_baseline_compliant_pct", false, componentsdk.CodeUnsupported, "GravityZone does not report whether a computer's operating system meets a baseline."},
	{"/patching/unsupported_os_count", "", true, componentsdk.CodeUnsupported, "GravityZone does not report whether a computer's operating system version still gets security updates."},
	{"/protection/edr_healthy_pct", "protection.edr_healthy_pct", false, componentsdk.CodeUnsupported, "GravityZone does not report whether the EDR sensor is running and reporting."},
}

// nloc locates a value in the normalized artifact.
func nloc(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: normalizedPath, Pointer: pointer}
}

// reasonOf is the availability reason for a value err left out.
func reasonOf(err error) string {
	switch componentsdk.Classify(err) {
	case componentsdk.CodePermissionDenied:
		return reasonPermissionDenied
	case componentsdk.CodeTooLarge:
		return reasonPartial
	}
	return reasonSourceError
}

// reading is one computer's protection readings, by control key.
type reading map[string]controlReading

// controlReading is one computer's state for one control. unread names the
// getManagedEndpointDetails value GravityZone left out, or sent as null,
// that made the state unknown. An unknown state from a value GravityZone
// did send would leave unread empty.
type controlReading struct {
	state  string
	unread string
}

// readingOf returns a computer's protection readings from its endpoint list
// row and its getManagedEndpointDetails answer. A computer without the agent
// has no modules, so each control fails. For a failed detail call it returns
// the call's error and no reading.
func readingOf(e bitdefender.Endpoint, details map[string]detailRead) (reading, *bitdefender.EndpointDetail, error) {
	if e.IsManaged != nil && !*e.IsManaged {
		fail := controlReading{state: stateFail}
		return reading{"antimalware_installed": fail, "antimalware_healthy": fail, "edr_installed": fail}, nil, nil
	}
	read, ok := details[e.ID]
	if !ok {
		return nil, nil, componentsdk.CodeError(componentsdk.CodeInternal, fmt.Errorf("the details of a managed computer were not read"))
	}
	if read.err != nil {
		return nil, nil, read.err
	}
	d := read.detail
	antimalware := moduleState(d.Modules, "antimalware")
	return reading{
		"antimalware_installed": antimalware,
		"antimalware_healthy":   antimalwareHealthy(antimalware, d.Agent),
		"edr_installed":         moduleState(d.Modules, "edrSensor"),
	}, d, nil
}

// moduleState is pass for a module GravityZone reports on and fail for one
// it reports off. GravityZone's modules object lists the modules installed
// on the computer, so a module it leaves out is not installed and fails. A
// module sent as null is unknown.
func moduleState(modules map[string]*bool, name string) controlReading {
	on, listed := modules[name]
	switch {
	case !listed:
		return controlReading{state: stateFail}
	case on == nil:
		return controlReading{state: stateUnknown, unread: "modules." + name}
	case *on:
		return controlReading{state: statePass}
	}
	return controlReading{state: stateFail}
}

// antimalwareHealthy passes a computer when its antimalware module is on
// with an active license and current signatures. It fails the computer when
// any one of them is known to be false. Otherwise it is unknown when
// GravityZone left one of them out.
func antimalwareHealthy(antimalware controlReading, agent *bitdefender.EndpointAgent) controlReading {
	license := controlReading{state: stateUnknown, unread: "agent"}
	signatures := license
	if agent != nil {
		license.unread, signatures.unread = "agent.licensed", "agent.signatureOutdated"
		if agent.Licensed != nil {
			license = controlReading{state: passIf(*agent.Licensed == bitdefender.LicenseActive)}
		}
		if agent.SignatureOutdated != nil {
			signatures = controlReading{state: passIf(!*agent.SignatureOutdated)}
		}
	}
	readings := []controlReading{antimalware, license, signatures}
	for _, r := range readings {
		if r.state == stateFail {
			return controlReading{state: stateFail}
		}
	}
	for _, r := range readings {
		if r.state == stateUnknown {
			return r
		}
	}
	return controlReading{state: statePass}
}

func passIf(ok bool) string {
	if ok {
		return statePass
	}
	return stateFail
}

// osFamily maps GravityZone's operatingSystemVersion name, such as
// "Windows 11 Pro" or "Ubuntu 24.04", to the schema's OS family.
func osFamily(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return "unknown"
	case strings.Contains(n, "windows"):
		return "windows"
	case strings.Contains(n, "macos"), strings.Contains(n, "mac os"), strings.Contains(n, "os x"):
		return "macos"
	}
	for _, linux := range []string{"linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "suse", "rocky", "almalinux"} {
		if strings.Contains(n, linux) {
			return "linux"
		}
	}
	return "other"
}

func managementState(e bitdefender.Endpoint) string {
	switch {
	case e.IsManaged == nil:
		return "unknown"
	case *e.IsManaged:
		return "managed"
	}
	return "unmanaged"
}

// lastSeenAt formats a getManagedEndpointDetails lastSeen as RFC 3339.
// GravityZone writes it without an offset, as in 2026-08-22T13:46:59, and the
// collector reads such a time as UTC. It returns false for a value it cannot
// parse.
func lastSeenAt(raw string) (string, bool) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format(time.RFC3339), true
	}
	if t, err := time.Parse("2006-01-02T15:04:05", raw); err == nil {
		return t.Format(time.RFC3339), true
	}
	return "", false
}

// protectionModules lists the modules GravityZone reports for a computer, in
// the schema's kinds. The antimalware module's health is the computer's
// antimalware_healthy reading.
func protectionModules(d *bitdefender.EndpointDetail, r reading) []ProtectionModule {
	modules := []ProtectionModule{}
	if d == nil {
		return modules
	}
	for _, m := range []struct{ name, kind string }{
		{"antimalware", "antimalware"},
		{"edrSensor", "edr"},
		{"firewall", "firewall"},
		{"deviceControl", "device_control"},
	} {
		on := d.Modules[m.name]
		if on == nil {
			continue
		}
		enabled := *on
		row := ProtectionModule{Kind: m.kind, Enabled: &enabled}
		if state := r["antimalware_healthy"].state; m.kind == "antimalware" && state != stateUnknown {
			healthy := state == statePass
			row.Healthy = &healthy
		}
		modules = append(modules, row)
	}
	return modules
}

// buildNormalized assembles the endpoint-posture artifact from the endpoint
// lists and the detail calls, and records the gaps of each value it leaves
// out.
func (c *Collector) buildNormalized(p *collectionPass) *Normalized {
	audit := p.level.AtLeast(componentsdk.LevelAudit)
	n := &Normalized{
		SchemaVersion: normalizedSchemaVersion,
		CollectedAt:   c.now().UTC().Format(time.RFC3339),
		Provider:      normalizedProvider,
		Scope: NormalizedScope{
			Description:              scopeDescription,
			MaxObservationAgeSeconds: int64(maxObservationAge / time.Second),
		},
		Availability: []Availability{},
	}
	for _, u := range unreadValues {
		if u.audit && !audit {
			continue
		}
		c.rec.NotCollectedCode(nloc(u.pointer), u.code, u.reason)
		if u.path != "" {
			n.Availability = append(n.Availability, Availability{Path: u.path, Reason: availabilityReason(u.code), Message: u.reason})
		}
	}

	fleetErr := p.fleetErr()
	n.Scope.DiscoveryComplete = c.discoveryComplete(fleetErr)
	computers := sortedComputers(p.computers)
	if fleetErr != nil {
		c.recordIncompleteDiscovery(p, n, fleetErr, audit)
	} else {
		c.applyFleet(p, n, computers, audit)
	}
	if audit {
		c.applyDevices(p, n, computers)
	}
	sortAvailability(n.Availability)
	return n
}

// discoveryComplete says whether every computer was read, given why the
// endpoint lists were not read in full. It is false when a list is longer
// than the collector reads. A failed call leaves it unknown, so it is nil
// with the call's gap.
func (c *Collector) discoveryComplete(fleetErr error) *bool {
	switch {
	case fleetErr == nil:
		return boolPtr(true)
	case componentsdk.Classify(fleetErr) == componentsdk.CodeTooLarge:
		return boolPtr(false)
	}
	c.rec.NotCollected(nloc("/scope/discovery_complete"), fleetErr)
	return nil
}

// recordIncompleteDiscovery records err's gap on the fleet and the
// percentages. Both need every computer.
func (c *Collector) recordIncompleteDiscovery(p *collectionPass, n *Normalized, err error, audit bool) {
	c.rec.NotCollected(nloc("/fleet"), err)
	c.rec.NotCollected(nloc("/protection"), err)
	n.Availability = append(n.Availability, Availability{Path: "fleet", Reason: reasonOf(err)})
	for _, m := range protectionMetrics {
		n.Availability = append(n.Availability, Availability{Path: m.path, Reason: reasonOf(err)})
	}
	if audit {
		c.rec.NotCollected(nloc("/scope/observed_device_count"), err)
		c.rec.NotCollected(nloc("/metric_coverage"), err)
	}
}

// applyFleet writes the fleet totals and the protection percentages. The
// percentages are left out when any computer's details were not read. A
// percentage is also left out when a computer's answer left out a value it
// needs, and metric_coverage counts that computer as unknown.
func (c *Collector) applyFleet(p *collectionPass, n *Normalized, computers []bitdefender.Endpoint, audit bool) {
	total := len(computers)
	present := total > 0
	n.Fleet = &NormalizedFleet{DevicesPresent: &present}
	if audit {
		observed := len(p.all)
		n.Scope.ObservedDeviceCount = &observed
		n.Fleet.DeviceCount = &total
		managed, unknown := 0, 0
		byOS := map[string]int{}
		for _, e := range computers {
			byOS[osFamily(e.OperatingSystemVersion)]++
			switch {
			case e.IsManaged == nil:
				unknown++
			case *e.IsManaged:
				managed++
			}
		}
		if unknown > 0 {
			c.rec.Partial(nloc("/fleet/managed_device_count"), unknown, componentsdk.CodeError(componentsdk.CodeInvalidResponse,
				fmt.Errorf("isManaged is missing for %d of %d computers in the endpoint lists", unknown, total)))
		} else {
			n.Fleet.ManagedDeviceCount = &managed
		}
		if total > 0 {
			n.Fleet.DevicesByOS = byOS
		}
	}

	coverage := map[string]*MetricCoverage{}
	unreported := map[string]*unreportedValues{}
	for _, m := range protectionMetrics {
		coverage[m.control] = &MetricCoverage{}
		unreported[m.control] = &unreportedValues{values: map[string]bool{}}
	}
	unread := 0
	var firstErr error
	for _, e := range computers {
		r, _, err := readingOf(e, p.details)
		if err != nil {
			unread++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, m := range protectionMetrics {
			cov := coverage[m.control]
			switch r[m.control].state {
			case statePass:
				cov.Passing++
			case stateFail:
				cov.Failing++
			default:
				cov.Unknown++
				if value := r[m.control].unread; value != "" {
					unreported[m.control].add(value)
				}
			}
		}
	}

	protection := &NormalizedProtection{}
	if audit {
		n.MetricCoverage = map[string]MetricCoverage{}
	}
	for _, m := range protectionMetrics {
		if unread > 0 {
			c.rec.Partial(nloc(m.pointer), unread, firstErr)
			n.Availability = append(n.Availability, Availability{Path: m.path, Reason: reasonOf(firstErr)})
			if audit {
				c.rec.Partial(nloc("/metric_coverage/"+m.path), unread, firstErr)
			}
			continue
		}
		cov := *coverage[m.control]
		if audit {
			n.MetricCoverage[m.path] = cov
		}
		// The schema leaves an unknown computer out of the share. When
		// GravityZone left out a value the reading needs, the computer is a
		// failed read instead, as for a failed detail call, so the share is
		// left out.
		if u := unreported[m.control]; u.computers > 0 {
			err := u.err(total)
			c.rec.Partial(nloc(m.pointer), u.computers, err)
			n.Availability = append(n.Availability, Availability{Path: m.path, Reason: reasonOf(err)})
			continue
		}
		pct := percentOf(cov.Passing, cov.Passing+cov.Failing)
		switch m.control {
		case "antimalware_installed":
			protection.AntimalwareInstalledPct = pct
		case "antimalware_healthy":
			protection.AntimalwareHealthyPct = pct
		case "edr_installed":
			protection.EDRInstalledPct = pct
		}
	}
	if protection.AntimalwareInstalledPct.Read || protection.AntimalwareHealthyPct.Read || protection.EDRInstalledPct.Read {
		n.Protection = protection
	}
}

// unreportedValues counts the computers whose reading for one control is
// unknown because getManagedEndpointDetails left out a value it needs, or
// sent it as null, and names those values.
type unreportedValues struct {
	computers int
	values    map[string]bool
}

func (u *unreportedValues) add(value string) {
	u.computers++
	u.values[value] = true
}

func (u *unreportedValues) err(total int) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("getManagedEndpointDetails gave no %s for %d of %d computers",
		strings.Join(slices.Sorted(maps.Keys(u.values)), " or "), u.computers, total))
}

// applyDevices writes one row per computer, up to EndpointsCap rows, ordered
// by hostname. The rows are left out when getEndpointsList failed. When only
// the Active Directory folder failed, the rows read stay with a partial gap.
func (c *Collector) applyDevices(p *collectionPass, n *Normalized, computers []bitdefender.Endpoint) {
	if p.listErr != nil {
		c.rec.NotCollected(nloc("/devices"), p.listErr)
		return
	}
	sorted := append([]bitdefender.Endpoint(nil), computers...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID < sorted[j].ID
	})
	dropped := 0
	if len(sorted) > EndpointsCap {
		dropped = len(sorted) - EndpointsCap
		sorted = sorted[:EndpointsCap]
	}
	rows := make([]Device, 0, len(sorted))
	for i, e := range sorted {
		row := Device{
			DeviceID:        e.ID,
			Hostname:        e.Name,
			OSFamily:        osFamily(e.OperatingSystemVersion),
			OSName:          e.OperatingSystemVersion,
			ManagementState: managementState(e),
			InScope:         true,
		}
		r, detail, err := readingOf(e, p.details)
		if err != nil {
			for _, field := range []string{"last_seen_at", "controls", "protection_modules"} {
				c.rec.NotCollected(nloc(fmt.Sprintf("/devices/%d/%s", i, field)), err)
			}
			rows = append(rows, row)
			continue
		}
		row.Controls = map[string]DeviceControl{}
		for _, m := range protectionMetrics {
			row.Controls[m.control] = DeviceControl{State: r[m.control].state}
		}
		modules := protectionModules(detail, r)
		row.ProtectionModules = &modules
		if detail != nil && detail.LastSeen != "" {
			if seen, ok := lastSeenAt(detail.LastSeen); ok {
				row.LastSeenAt = seen
			} else {
				c.rec.NotCollectedCode(nloc(fmt.Sprintf("/devices/%d/last_seen_at", i)), componentsdk.CodeInvalidResponse,
					"The lastSeen time in getManagedEndpointDetails is not in a format the collector reads.")
			}
		}
		rows = append(rows, row)
	}
	n.Devices = &rows
	switch {
	case p.adErr != nil:
		c.rec.Partial(nloc("/devices"), 0, p.adErr)
	case dropped > 0:
		c.rec.Partial(nloc("/devices"), dropped, componentsdk.CodeError(componentsdk.CodeTooLarge,
			fmt.Errorf("devices: kept the first %d rows and left out %d", EndpointsCap, dropped)))
	}
}

// sortedComputers orders the computers by endpoint ID, so a gap names the
// same failed detail call whatever order GravityZone lists them in.
func sortedComputers(computers []bitdefender.Endpoint) []bitdefender.Endpoint {
	out := append([]bitdefender.Endpoint(nil), computers...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortAvailability(entries []Availability) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Reason < entries[j].Reason
	})
}
