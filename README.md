# libgoblin

![say the right words](https://s-media-cache-ak0.pinimg.com/736x/1b/6a/aa/1b6aaa2bae005e2fed84b1a7c32ecb1b.jpg)

Libgoblin is _most_ of the ELF binary parser and loader which [dryad](http://github.com/m4b) implemented, and which has now been extracted into a crate, so that:

1. the Rust ecosystem can have yet another ELF parsing library,
2. I can use this most excellent parser and loader for other, future projects.

Essentially, it follows closely the work I did on [rdr](http://github.com/m4b/rdr).  In time, I'll add mach and PE targets - for now, you'll just have to be patient, as I have a lot of work to do.

I will also eventually add an ELF32 target, which will support feature based compilation (since dryad needs as little symbols, and hence relocations, as possible).

More to come (maybe).
