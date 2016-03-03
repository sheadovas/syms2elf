# ida-syms2elf

The plugin export the symbols (for the moment only functions) recognized by Hex-Rays's IDA Pro to the ELF symbol table. This allows us to use the power of IDA in recognizing functions (analysis, FLIRT signatures, manual creation, renaming, etc), but not be limited to the exclusive use of this tool.

Supports 32 and 64-bits file format.

## INSTALLATION

Simply, copy `ida-symbs2elf.py` to the IDA's plugins folder.

## EXAMPLE

Based on a full-stripped ELF:

```
$ file test1_x86_stripped 
test1_x86_stripped: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, stripped
```

Rename some functions in IDA, run `syms2elf` in the plugin's menu and select the output file.

![Output log](https://cloud.githubusercontent.com/assets/1675387/13477862/a02aa742-e0ce-11e5-835e-3a0992a3f171.png)

After that:

```
$ file test1_x86_unstripped 
test1_x86_unstripped: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped
```

Now, you can open it with radare2, gdb, etc. and analyzing in a more comfortable way.

![r2 unstripped](https://cloud.githubusercontent.com/assets/1675387/13478524/b93b254c-e0d1-11e5-9512-fc0990f28bbe.png)

## AUTHORS

  * Daniel García (@danigargu)
  * Jesús Olmos (@sha0coder)

## CONTACT 

Any comment or request will be highly appreciated :-)

