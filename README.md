# DexAccessModifier [![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FDiamondMiner88%2FDexAccessModifier&count_bg=%2379C83D&title_bg=%23555555&icon=github.svg&icon_color=%23E7E7E7&title=views&edge_flat=true)](https://hits.seeyoufarm.com)
Lightweight & very fast native (rust) android lib for changing all access modifiers to public.\
This was primarily written for [Aliucord](https://github.com/Aliucord/Aliucord), to make making plugins easier & faster (no reflection).\
Used in combination with my fork-of-a-fork of [jadx](https://github.com/DiamondMiner88/dex2jar/tree/make-public) to use for building plugins against the Discord apk.\

## Building Prerequisites
1. Install the rust toolchain
2. `rustup target add aarch64-linux-android armv7-linux-androideabi`
3. `cargo install cargo-ndk`

## Benchmarks
