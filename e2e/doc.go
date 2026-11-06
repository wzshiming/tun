// Package e2e holds the end-to-end tests, which open real TUN devices, change the host's routes, bind sockets to
// its default interface and load the real wintun.dll, driving only the public API and the internal/elevate seam.
//
// Every test skips unless TUN_E2E=1. With it set, each test runs when the process has what it needs:
//   - macOS and Linux: TestE2EHelper runs unprivileged and starts its helper with `sudo -n`, so it needs passwordless
//     sudo; TestE2ERoot needs root and an IPv4 default route.
//   - Windows: the TUN tests need an elevated process and an embedded wintun.dll (amd64, arm64);
//     TestE2EWindowsHelperRunas also needs TUN_E2E_RUNAS=1, as it goes through UAC.
//   - The bypass tests need a default route; on Linux before 5.7 SO_BINDTODEVICE needs root.
//
// The helper is this test binary itself: TestMain runs tun.Helper when it is started as `<binary> tun-helper …`.
package e2e
