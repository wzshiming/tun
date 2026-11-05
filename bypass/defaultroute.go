package bypass

// routeCandidate is one default route of a family with the state of the interface it leaves through.
type routeCandidate struct {
	Index       int
	RouteMetric uint32
	IfaceMetric uint32
	Up          bool
	Loopback    bool
}

// pickDefaultRoute returns the index of the usable candidate with the lowest route plus interface metric, ties going to the lowest index.
func pickDefaultRoute(candidates []routeCandidate) (int, error) {
	index, best, found := 0, uint64(0), false
	for _, c := range candidates {
		if !c.Up || c.Loopback {
			continue
		}
		metric := uint64(c.RouteMetric) + uint64(c.IfaceMetric)
		if !found || metric < best || (metric == best && c.Index < index) {
			index, best, found = c.Index, metric, true
		}
	}
	if !found {
		return 0, ErrNoDefaultRoute
	}
	return index, nil
}
