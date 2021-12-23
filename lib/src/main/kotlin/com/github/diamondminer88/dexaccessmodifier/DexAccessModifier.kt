package com.github.diamondminer88.dexaccessmodifier

class DexAccessModifier {
    private companion object {
        var initialized: Boolean = false
    }

    init {
        if (!initialized) {
            System.loadLibrary("dexaccessmodifier")
            init("info")
        }
    }

    private external fun init(logLevel: String)

    external fun run(inputPath: String, outputPath: String)
}
