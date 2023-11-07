## Overview

This repository contains a small KVM timer demo. See the relevant [x86.lol post](https://x86.lol/).

## Running with Nix

Install [Nix](https://nix.dev/install-nix#install-nix) and enable [Nix Flakes](https://nixos.wiki/wiki/Flakes).

Then you can run the example without cloning this repo:

```console
$ nix run github:blitz/kvm-timer-demo
```

or after cloning this repo:

```console
$ nix run
```

## Build Requirements

- nasm
- xxd
- g++ >= 4.8.1
- make

## Execution Requirements

- access to /dev/kvm

## Build

```console
$ make
```

## Running

```console
$ ./timer
```
