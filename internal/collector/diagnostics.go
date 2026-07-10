package collector

// diagnostics collects permission and availability problems encountered
// during a run, so a degraded surface can be explained in the output
// instead of failing the whole collection. Mirrors the same pattern used by
// epack-collector-github.
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

// toDiagnostics converts the accumulator into the output struct.
func (d *diagnostics) toDiagnostics() Diagnostics {
	return Diagnostics{
		PermissionErrors: d.permissionErrors,
		Warnings:         d.warnings,
	}
}
