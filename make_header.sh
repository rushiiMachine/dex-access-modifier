cd ./lib/src/main/kotlin/com/github/diamondminer88/dexaccessmodifier || exit
kotlinc DexAccessModifier.kt
javah -o "DexAccessModifier.h" -force -classpath . com.github.diamondminer88.dexaccessmodifier.DexAccessModifier
rm -rf com META-INF
