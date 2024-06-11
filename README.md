- Get the code
```
git clone --recurse-submodules https://github.com/sergey-senozhatsky/snoops.git
```

- Install required dependencies
```
apt install cmake clang libelf1 libelf-dev zlib1g-dev libc++-dev libc++abi-dev
```

- Compile the code
```
cmake .
make
```

- Run the snoops, e.g.
```
memsnoop -p $(pidof process)
```

Note, the kernel should be compiled with `CONFIG_KPROBES`.
