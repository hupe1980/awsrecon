# AWSrecon
![Build Status](https://github.com/hupe1980/awsrecon/workflows/build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/awsrecon.svg)](https://pkg.go.dev/github.com/hupe1980/awsrecon)
> AWSrecon is a tool for reconnaissance AWS cloud environments. It helps security professionals find possible vulnerabilities and exploitable attack paths in AWS cloud infrastructures.

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
  help         Help about any command
  instances    Enumerate ec2 instances
  principals   Enumerate principals
  records      Enumerate dns records
  repos        Enumerate codecommit repositories
  secrets      Enumerate secrets
  stacks       Enumerate cloudformation stacks
  tags         Enumerate tags

Flags:
  -h, --help                help for awsrecon
  -o, --output string       output CSV filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
      --timeout duration    timeout for network requests (default 15s)
  -A, --user-agent string   user-agent ot use (default "awsrecon")
  -v, --version             version for awsrecon

Use "awsrecon [command] --help" for more information about a command.
```

## License
[MIT](LICENCE)
