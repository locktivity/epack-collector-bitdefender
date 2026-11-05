package collector

import "github.com/locktivity/epack/componentsdk"

// diagnostics collects permission and availability problems encountered
// during a run, so a degraded surface can be explained in the output
// instead of failing the whole collection. Mirrors the same pattern used by
// epack-collector-github. The collector result records the same problems as
// gaps, by value.
type diagnostics struct {
	permissionErrors []string
	warnings         []string
}

// surfacePermissionDenied records that a surface was skipped because the
// GravityZone API key isn't authorized for the API it needed.
func (d *diagnostics) surfacePermissionDenied(surface, neededAPI string) {
	d.permissionErrors = append(d.permissionErrors,
		surface+": API key is not authorized for the "+neededAPI+" API")
}

// surfaceWarning records a non-fatal problem (e.g. a single endpoint's
// detail call failed) that degrades a surface without failing the run.
func (d *diagnostics) surfaceWarning(surface, msg string) {
	d.warnings = append(d.warnings, surface+": "+msg)
}

// surfaceFailed records a surface a failed call left out: as a permission
// error when the key lacks the API, and as a warning otherwise.
func (d *diagnostics) surfaceFailed(surface, neededAPI, warning string, err error) {
	if componentsdk.Classify(err) == componentsdk.CodePermissionDenied {
		d.surfacePermissionDenied(surface, neededAPI)
		return
	}
	d.surfaceWarning(surface, warning)
}

// toDiagnostics converts the accumulator into the output struct.
func (d *diagnostics) toDiagnostics() Diagnostics {
	return Diagnostics{
		PermissionErrors: d.permissionErrors,
		Warnings:         d.warnings,
	}
}
