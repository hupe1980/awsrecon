# Enumerate secrets
```
Usage:
  awsrecon secrets [flags]

Flags:
  -d, --decrypt                        decrypt secret
  -e, --entropy float                  minimum entropy
  -h, --help                           help for secrets
      --high-entropy-threshold float   high entropy threshold (default 3.5)
      --ignore-service strings         ignore services when enumeration
      --verify                         verify secrets

Global Flags:
  -o, --output string       output filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
  -A, --user-agent string   user-agent to use (default "awsrecon")
```