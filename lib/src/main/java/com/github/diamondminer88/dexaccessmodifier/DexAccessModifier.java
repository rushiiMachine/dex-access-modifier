package com.github.diamondminer88.dexaccessmodifier;

@SuppressWarnings("unused")
public class DexAccessModifier {
    private static boolean initialized = false;

    public DexAccessModifier() {
        this("info");
    }

    /**
     * Note that the logLevel will remain the same once the first instance of this class has been created
     * @param logLevel One of the following: debug info warn error
     */
    public DexAccessModifier(String logLevel) {
        if (!initialized) {
            System.loadLibrary("dexaccessmodifier");
            init(logLevel);
            initialized = true;
        }
    }

    private native void init(String logLevel);

    /**
     * Run the access modifier on a certain dex file
     * @param inputPath Input file
     * @param outputPath Output file
     */
    public native void run(String inputPath, String outputPath);
}
