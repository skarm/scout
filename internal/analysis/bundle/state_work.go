package bundle

// Copy into private state, charging each visited entry before touching it.
// A failed copy must be discarded by its caller.
func copyBundleEntries[V any](b *bundleAnalysis, destination, original map[string]V) bool {
	if !b.stateReady() {
		return false
	}

	for name, value := range original {
		if !b.step() {
			return false
		}

		destination[name] = value
	}

	return true
}

func (b *bundleAnalysis) stateReady() bool {
	if err := b.ctx.Err(); err != nil && b.err == nil {
		b.err = err
	}

	return b.err == nil
}
