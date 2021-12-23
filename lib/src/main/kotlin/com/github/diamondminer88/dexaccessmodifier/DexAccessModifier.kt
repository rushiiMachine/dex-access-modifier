package com.github.diamondminer88.dexaccessmodifier

class DexAccessModifier(logLevel: String) {
    private companion object {
        var initialized: Boolean = false
    }

    init {
        if (!initialized) {
            System.loadLibrary("dexaccessmodifier")
            init(logLevel)
            initialized = true
        }
    }

    private external fun init(logLevel: String)

    external fun run(inputPath: String, outputPath: String)
}
