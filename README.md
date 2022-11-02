# awsrecon
> AWSrecon is a tool for reconnaissance AWS cloud environments. It helps security professionals find possible vulnerabilities and exploitable attack paths in AWS cloud infrastructures.

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
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
      --timeout duration    timeout for network requests (default 15s)
  -A, --user-agent string   user-agent ot use (default "awsrecon")
  -v, --version             version for awsrecon

Use "awsrecon [command] --help" for more information about a command.
```

## License
[MIT](LICENCE)
