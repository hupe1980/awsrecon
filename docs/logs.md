# Enumerate cloudwatch logs
```
Usage:
  awsrecon logs [flags]

Flags:
      --end-time int                end of the time range (default open end)
      --filter-pattern string       filter pattern to match
      --group-name-prefix string    group name prefix to match (default "/aws/lambda")
  -h, --help                        help for logs
      --start-time int              start of the time range (default last 24h)
      --stream-name-prefix string   stream name prefix to match (default "2022")
      --verify                      verify secrets

Global Flags:
  -o, --output string       output filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
  -A, --user-agent string   user-agent to use (default "awsrecon")
```