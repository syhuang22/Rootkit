cmd_/home/sh694/Rootkit/sneaky_mod.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000  --build-id  -T ./scripts/module-common.lds -o /home/sh694/Rootkit/sneaky_mod.ko /home/sh694/Rootkit/sneaky_mod.o /home/sh694/Rootkit/sneaky_mod.mod.o;  true