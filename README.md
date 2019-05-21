# Go Legacy Crypto

A home for legacy crypto algorithms in Go, which are not in go crytpo or x/crypto. This project was inspired by the [deprecation of older crypto implementations](https://github.com/golang/go/issues/30141) and the [discussion of adding more deprecated hashes](https://github.com/golang/go/issues/32087) in x/crypto.

## Contributing

Open an issue/PR if you'd like to see more algorithms. Please provide links to publications, reference implementations, etc.

## Install:

```sh
go get -u  github.com/y3sh/go-legacy-crypto/ripemd320
go get -u  github.com/y3sh/go-legacy-crypto/whirlpool
go get -u  github.com/y3sh/go-legacy-crypto/skipjack32
go get -u  github.com/y3sh/go-legacy-crypto/...
```

## Test

```sh
make test
```
