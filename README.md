# tun

Captures a machine's IP traffic into a TUN device for your program to serve flow by flow.

## Platforms

| | Prompt | Notes |
| --- | --- | --- |
| macOS | `osascript` | the helper hands the device descriptor to the parent and exits |
| Linux | `pkexec` | as macOS; needs the `ip` command; unprivileged `SO_BINDTODEVICE` needs kernel 5.7+ |
| Windows 10+ | UAC on each `Open` | 386, amd64 and arm64; the elevated helper runs a Wintun adapter and relays packets to the parent over a token-checked loopback connection; the first `Open` installs the Wintun driver |

## License

Licensed under the MIT License. See [LICENSE](https://github.com/wzshiming/xet/blob/master/LICENSE) for the full license text.
