# Enumerate ec2 instances
```
Usage:
  awsrecon instances [flags]

Flags:
  -h, --help                           help for instances
      --high-entropy-threshold float   high entropy threshold (default 3.5)
      --my-ip ip                       ip to check open ports
  -s, --states strings                 instance states (default all states)
      --verify                         verify secrets

Global Flags:
  -o, --output string       output filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
  -A, --user-agent string   user-agent to use (default "awsrecon")
```