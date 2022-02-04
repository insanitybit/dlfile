# dlfile

dlfile is a very simple, straightforward CLI to download a file, except it...

1. Only downloads over HTTPS
2. Requires TLS 1.2 or higher
3. Executes in a seccomp sandbox
4. Uses `trust-dns`, supporting DNS over TLS


### Install

`cargo install dlfile`


### Example
`dlfile --from="https://sh.rustup.rs" --to="./rustup.sh`

### Usage

```
dlfile 0.2.0

USAGE:
    dlfile [FLAGS] [OPTIONS] --from <from> --to <to>

FLAGS:
    -h, --help          Prints help information
        --no-sandbox    [UNSAFE] Indicates that you want to run without the default sandbox
    -V, --version       Prints version information

OPTIONS:
    -f, --from <from>            The fully qualified URL with an https scheme to download from [env: FROM=]
        --max-size <max-size>    Maximum number of bytes to write to disk before aborting [env: MAX_SIZE=]  [default:
                                 1GB]
        --min-tls <min-tls>      Minimum tls version, one of `v1.2` or `v1.3` [env: MIN_TLS=]  [default: v1.2]
    -t, --to <to>                The file system path, including a file name, for where to write the file to [env: TO=]
```
