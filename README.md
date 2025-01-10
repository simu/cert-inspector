# cert-inspector

A simple tool to inspect files which contain one or more PEM-encoded certificates.

## Prerequisites

* Rust compiler

## Building

```
cargo build --release
```

## Printing basic information about all certificates in a bundle

To print basic information for each certificate in a bundle, you can use `cert-inspector info`:

```
cert-inspector info ca-bundle.crt
```

## Splitting a certificate bundle into individual files

To split a certificate bundle file into individual files containing one certificate each, you can use `cert-inspector split`:

```
cert-inspector split ca-bundle.crt ca
```

The second argument is optional and allows you to define the prefix for the split files.
The given command will produce files `ca-0.crt`-`ca-N.crt` for a `ca-bundle.crt` that contains N+1 certificates.
If the second argument is omitted, the command will use the base name of the bundle file as the prefix.
