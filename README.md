# pflogsumm-go

A Go reimplementation of [pflogsumm](http://jimsun.LinxNet.com/postfix_contrib.html), the Postfix log summarizer originally written in Perl by James S. Seymour (Release 1.1.5).

This is a 100% pure Go program with no external dependencies. It produces output identical to the original Perl tool.

## Installation

### From source

```bash
go install github.com/vignemail1/pflogsumm-go@latest
```

### Build from source

```bash
git clone https://github.com/vignemail1/pflogsumm-go.git
cd pflogsumm-go
go build -o pflogsumm .
```

## Usage

```
pflogsumm [options] [file1 [file2 ...]]
```

If no files are specified, reads from stdin. Output is to stdout.

### Examples

Produce a report of previous day's activities:

```bash
pflogsumm -d yesterday /var/log/maillog
```

A report of prior week's activities (after logs rotated):

```bash
pflogsumm /var/log/maillog.0
```

What's happened so far today:

```bash
pflogsumm -d today /var/log/maillog
```

Pipe from journalctl:

```bash
journalctl -u postfix --since yesterday --no-pager | pflogsumm
```

### Options

| Option | Description |
|--------|-------------|
| `--bounce-detail <cnt>` | Limit detailed bounce reports to top `<cnt>`. 0 to suppress. |
| `-d today\|yesterday` | Generate report for just today or yesterday. |
| `--time-range <start> <end>` | Generate report for specified period (Unix epoch seconds). |
| `--deferral-detail <cnt>` | Limit detailed deferral reports to top `<cnt>`. 0 to suppress. |
| `--detail <cnt>` | Sets all `--*-detail`, `-h` and `-u` to `<cnt>`. Overridden by individual settings. |
| `-e` | Extended (per-message) detail report. |
| `-h <cnt>` | Top `<cnt>` to display in host/domain reports. 0 = none. |
| `--help` | Show usage and exit. |
| `-i`, `--ignore-case` | Case-insensitive email address handling. |
| `--iso-date-time` | Use ISO 8601 date/time formats. |
| `-m`, `--uucp-mung` | Modify UUCP-style bang-paths. |
| `--mailq` | Run "mailq" command at end of report. |
| `--no-no-msg-size` | Suppress "Messages with no size data" report. |
| `--problems-first` | Emit problems reports before normal stats. |
| `--rej-add-from` | Append sender address to reject report listings. |
| `-q` | Quiet mode: don't print headings for empty reports. |
| `--reject-detail <cnt>` | Limit detailed reject/warn/hold/discard reports. 0 to suppress. |
| `--smtp-detail <cnt>` | Limit detailed smtp delivery failure reports. 0 to suppress. |
| `--smtpd-stats` | Generate smtpd connection statistics. |
| `--smtpd-warning-detail <cnt>` | Limit detailed smtpd warnings. 0 to suppress. |
| `--syslog-name=<name>` | Set syslog name to look for (default: "postfix"). |
| `-u <cnt>` | Top `<cnt>` in user reports. 0 = none. |
| `--verbose-msg-detail` | Display full reason strings (not truncated). |
| `--verp-mung[=<n>]` | VERP address munging. `=2` for aggressive mode. |
| `--version` | Print version and exit. |
| `--zero-fill` | Zero-fill arrays for column alignment. |

### Default values

- `-h`: 20
- `-u`: 20
- `--bounce-detail`: 20
- `--deferral-detail`: 20
- `--reject-detail`: 20
- `--smtp-detail`: 20
- `--smtpd-warning-detail`: 20

## Reports Generated

- **Grand Totals**: messages received, delivered, forwarded, deferred, bounced, rejected, held, discarded; bytes received/delivered; sender/recipient counts
- **Per-Day Traffic Summary** (multi-day only)
- **Per-Hour Traffic Summary** (daily averages for multi-day)
- **Host/Domain Summary**: Message delivery and received summaries
- **SMTPD Connection Statistics** (with `--smtpd-stats`)
- **User Reports**: Senders/Recipients by message count and size
- **Problem Reports**: Deferrals, bounces, rejects, warnings, holds, discards, SMTP failures, warnings, fatal errors, panics, master daemon messages
- **Message Detail** (with `-e`)
- **Current Mail Queue** (with `--mailq`)

## Log Format Support

Supports both traditional syslog and RFC 3339 timestamp formats:

- Traditional: `Mon DD HH:MM:SS hostname process[pid]: message`
- RFC 3339: `YYYY-MM-DDTHH:MM:SS[.nnn][+-]HH:MM hostname process[pid]: message`

## CI/CD

CI runs automatically on every push and pull request to `main`, running vet, tests, and build verification.

### Creating a Release

To create a release with pre-built binaries for all platforms:

```bash
git tag v1.x.x
git push origin v1.x.x
```

This triggers the release workflow which builds static binaries for Linux (amd64, arm64, arm), macOS (amd64, arm64), FreeBSD (amd64), and Windows (amd64), then publishes them as a GitHub Release with SHA256 checksums.

Pre-built binaries are available on the [GitHub Releases](https://github.com/vignemail1/pflogsumm-go/releases) page.

## Credits

Original Perl pflogsumm by James S. Seymour. Go reimplementation by the pflogsumm-go contributors.

## License

GNU General Public License v2.0 - see [LICENSE](LICENSE) for details.
