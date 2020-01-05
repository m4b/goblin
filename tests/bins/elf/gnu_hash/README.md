# How to generate hello.so file

With 64-bit gcc:

```bash
% gcc -o hello.so helloworld.c -Wl,--as-needed -shared -fPIC
% readelf --dyn-syms hello.so

Symbol table '.dynsym' contains 13 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
     5: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)
     6: 0000000000201030     0 NOTYPE  GLOBAL DEFAULT   22 _edata
     7: 000000000000065a    33 FUNC    GLOBAL DEFAULT   12 helloWorld
     8: 0000000000201038     0 NOTYPE  GLOBAL DEFAULT   23 _end
     9: 0000000000201030     0 NOTYPE  GLOBAL DEFAULT   23 __bss_start
    10: 000000000000067b    43 FUNC    GLOBAL DEFAULT   12 main
    11: 0000000000000520     0 FUNC    GLOBAL DEFAULT    9 _init
    12: 00000000000006a8     0 FUNC    GLOBAL DEFAULT   13 _fini
```

Or in 32-bit mode (one might need to install `gcc-multilib` on Ubuntu):

```bash
% gcc -o hello.so helloworld.c -Wl,--as-needed -shared -fPIC
% readelf --dyn-syms hello32.so

Symbol table '.dynsym' contains 13 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.0 (2)
     3: 00000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.1.3 (3)
     4: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
     6: 00002018     0 NOTYPE  GLOBAL DEFAULT   22 _edata
     7: 000004ed    49 FUNC    GLOBAL DEFAULT   12 helloWorld
     8: 0000201c     0 NOTYPE  GLOBAL DEFAULT   23 _end
     9: 00002018     0 NOTYPE  GLOBAL DEFAULT   23 __bss_start
    10: 0000051e    66 FUNC    GLOBAL DEFAULT   12 main
    11: 0000038c     0 FUNC    GLOBAL DEFAULT    9 _init
    12: 00000564     0 FUNC    GLOBAL DEFAULT   13 _fini

```
