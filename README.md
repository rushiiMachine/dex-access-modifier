# DexAccessModifier [![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FDiamondMiner88%2FDexAccessModifier&count_bg=%2379C83D&title_bg=%23555555&icon=github.svg&icon_color=%23E7E7E7&title=views&edge_flat=true)](https://hits.seeyoufarm.com)
Lightweight & lightning fast native (rust) android lib for changing all access modifiers to public.\
This was primarily written for [Aliucord](https://github.com/Aliucord/Aliucord), to make making plugins easier & faster (no reflection).\
Used in combination with my fork-of-a-fork of [jadx](https://github.com/DiamondMiner88/dex2jar/tree/make-public) to use for building plugins against the Discord apk.

## NOTE:
This project is currently in WIP, however should work (excluding private instance methods).\
Because of [this](https://android.googlesource.com/platform/art/+/04be5f6/libdexfile/dex/dex_file_verifier.cc#3527) check in the android src, we cannot change private instance methods -> public,\
since it now belongs to the virtual methods table. Currently attempting to write a tool to nop that check,
however it may prove to be impossible.

## Building Prerequisites
1. Install the rust toolchain
2. `rustup target add aarch64-linux-android armv7-linux-androideabi`
3. `cargo install --force cargo-ndk`

## Benchmarks
Run on a fully charged Pixel 2:
1. 11mb 11k classes, 57k methods, 65k fields in **78ms** (Discord apk classes.dex)
2. 10.7mb 11k classes, 56k methods, 26k fields in **65ms** (classes2.dex)
3. 7mb 8k classes, 39k methods, 44k fields in **45ms** (classes3.dex)
