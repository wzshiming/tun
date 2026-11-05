package tun

import (
	"fmt"
	"testing"
)

func TestAdapterGUIDSpellsTheNameGUID(t *testing.T) {
	b := nameGUID("tt0")
	want := fmt.Sprintf("{%X-%X-%X-%X-%X}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	if got := adapterGUID(Config{Name: "tt0"}).String(); got != want {
		t.Errorf("adapterGUID(tt0) = %s, want %s", got, want)
	}
}

func TestAdapterGUIDDefaultsToTheNameTun(t *testing.T) {
	if got, want := adapterGUID(Config{}), adapterGUID(Config{Name: "tun"}); got != want {
		t.Errorf("adapterGUID(no name) = %v, want that of tun, %v", got, want)
	}
}
