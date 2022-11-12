# Enumerate cloudformation stacks
```
Usage:
  awsrecon stacks [flags]

Flags:
  -e, --entropy float                  minimum entropy
  -h, --help                           help for stacks
      --high-entropy-threshold float   high entropy threshold (default 3.5)
      --ignore-cdk-asset-parameter     ignore cdk asset parameter
      --verify                         verify secrets

Global Flags:
  -o, --output string       output filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
  -A, --user-agent string   user-agent to use (default "awsrecon")
```