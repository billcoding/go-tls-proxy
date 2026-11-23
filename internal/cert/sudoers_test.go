package cert

import (
	"strings"
	"testing"
)

func TestSudoersFragmentLeastPrivilege(t *testing.T) {
	binary := "/srv/go-tls-proxy/go-tls-proxy"
	text := SudoersFragment("go-tls-proxy", binary)
	want := "go-tls-proxy ALL=(root) NOPASSWD: " + binary + " fw80 open *, " + binary + " fw80 close *\n"
	if !strings.Contains(text, want) {
		t.Fatal(text)
	}
	if strings.Contains(text, "/data/opt/go-tls-proxy") {
		t.Fatal(text)
	}
	if strings.Contains(text, "/srv/go-tls-proxy/fw80") {
		t.Fatal(text)
	}
	if strings.Contains(text, "NOPASSWD: "+binary+"\n") {
		t.Fatal(text)
	}
	if strings.Contains(text, "ALL=(ALL)") || strings.Contains(text, "NOPASSWD: ALL") || strings.Contains(strings.ToUpper(text), "NOPASSWD:ALL") {
		t.Fatal(text)
	}
}
