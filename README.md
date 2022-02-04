# dlfile

```
USAGE:
    dlfile [FLAGS] --from <from> --to <to>

FLAGS:
    -h, --help          Prints help information
        --no-sandbox    [UNSAFE] Indicates that you want to run without the default sandbox
    -V, --version       Prints version information

OPTIONS:
    -f, --from <from>    The fully qualified URL with an https scheme to download from [env: FROM=]
    -t, --to <to>        The file system path, including a file name, for where to write the file to [env: TO=]
```

### Notes
1. Only downloads over HTTPS
2. Requires TLS 1.2 or higher
3. Executes in a seccomp sandbox
4. Uses `trust-dns`, supporting DNS over TLS
