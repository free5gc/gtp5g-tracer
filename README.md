# gtp5g-tracer

## Prerequisites

Build gtp5g.ko with BTF support
```sh
$ cp /sys/kernel/btf/vmlinux /usr/lib/modules/$(uname -r)/build/
$ cd <GTP5G_SOURCE_DIR>
$ make
$ sudo make install
```

## Build

```sh
$ make dep # for first time
$ make
```

## Run

```sh
$ sudo ./main
```

## Debugging

To view the trace output, you can use the following command:

```sh
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```