# AWSrecon
![Build Status](https://github.com/hupe1980/awsrecon/workflows/build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/awsrecon.svg)](https://pkg.go.dev/github.com/hupe1980/awsrecon)
> AWSrecon is a tool for reconnaissance AWS cloud environments. It helps security professionals find possible vulnerabilities and exploitable attack paths in AWS cloud infrastructures.

## Features

- Enumerates internal/external endpoints as attacking starting point or for lateral movement 
- Mines secrets in envs, tags, stacks and more
- Detects dangling dns entries (subdomain takeover)
- Lists iam policies that have the potential for privilege escalation or data exfiltration (coming soon)
- Gives hints for further investigations
- ...

## Installing
You can install the pre-compiled binary in several different ways

### homebrew tap:
```bash
brew tap hupe1980/awsrecon
brew install awsrecon
```
### scoop:
```bash
scoop bucket add awsrecon https://github.com/hupe1980/awsrecon-bucket.git
scoop install awsrecon
```

### deb/rpm/apk:
Download the .deb, .rpm or .apk from the [releases page](https://github.com/hupe1980/awsrecon/releases) and install them with the appropriate tools.

### manually:
Download the pre-compiled binaries from the [releases page](https://github.com/hupe1980/awsrecon/releases) and copy to the desired location.


## How to use
```
Usage:
  awsrecon [command]

Available Commands:
  buckets      Enumerate s3 buckets
  completion   Generate the autocompletion script for the specified shell
  download-iam Download iam definitions
  endpoints    Enumerate endpoints
  envs         Enumerate environment variables
  filesystems  Enumerate filesystems
  functions    Enumerate lambda functions
  help         Help about any command
  instances    Enumerate ec2 instances
  logs         Enumerate cloudwatch logs
  principals   Enumerate iam principals
  records      Enumerate dns records
  repos        Enumerate codecommit repositories
  secrets      Enumerate secrets
  stacks       Enumerate cloudformation stacks
  tags         Enumerate tags

Flags:
  -h, --help                help for awsrecon
  -o, --output string       output filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
  -A, --user-agent string   user-agent to use (default "awsrecon")
  -v, --version             version for awsrecon

Use "awsrecon [command] --help" for more information about a command.
```

## Available Commands
|Name|Description
|-|-
|[buckets](/docs/buckets.md)|Enumerate s3 buckets|
|[endpoints](/docs/endpoints.md)|Enumerate endpoints|
|[envs](/docs/envs.md)|Enumerate environment variables|
|[filesystems](/docs/filesystems.md)|Enumerate filesystems|
|[functions](/docs/functions.md)|Enumerate lambda functions|
|[instances](/docs/instances.md)|Enumerate ec2 instances|
|[logs](/docs/logs.md)|Enumerate cloudwatch logs|
|[principals](/docs/principals.md)|Enumerate iam principals|
|[records](/docs/records.md)|Enumerate dns records|
|[repos](/docs/repos.md)|Enumerate codecommit repos|
|[secrets](/docs/secrets.md)|Enumerate secrets|
|[stacks](/docs/stacks.md)|Enumerate cloudformation stacks|
|[tags](/docs/tags.md)|Enumerate tags|

## License
[MIT](LICENCE)
