# DexAccessModifier [![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FDiamondMiner88%2FDexAccessModifier&count_bg=%2379C83D&title_bg=%23555555&icon=github.svg&icon_color=%23E7E7E7&title=views&edge_flat=true)](https://hits.seeyoufarm.com)

Lightweight & lightning fast native (rust) android lib for changing all access modifiers to public.\
This was primarily written for [Aliucord](https://github.com/Aliucord/Aliucord), to make making plugins easier &
faster (no reflection).\
Used in combination with my fork-of-a-fork of [jadx](https://github.com/DiamondMiner88/dex2jar/tree/make-public) to use
for building plugins against the Discord apk.

## NOTE:

This project is currently in WIP, however should work (excluding private instance methods).\
Because of [this](https://android.googlesource.com/platform/art/+/04be5f6/libdexfile/dex/dex_file_verifier.cc#3527)
check in the android src, we cannot change private instance methods -> public,\
since it now belongs to the virtual methods table. Currently, I'm attempting to write a tool to noop that check.

## Benchmarks

Run on a fully charged Pixel 2:

Discord apk classes:

| Source       | Size   | Time | Classes | Methods | Fields | 
|--------------|--------|------|---------|---------|--------|
| classes.dex  | 11mb   | 78ms | 11k     | 57k     | 65k    |
| classes2.dex | 10.7mb | 65ms | 11k     | 56k     | 26k    |
| classes3.dex | 7mb    | 45ms | 8k      | 39k     | 45k    |

## Building Prerequisites

1. Install the rust toolchain
2. `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android`
3. `cargo install --force cargo-ndk`
