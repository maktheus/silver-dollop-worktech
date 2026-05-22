# Obfuscate everything in the detection module — makes static analysis harder for attackers.
# The enum values/names must be kept so the UI can display them.
-keepclassmembers enum com.incognia.guardapp.detection.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
    public final ** name();
    public final int ordinal();
}

# Keep data class component functions used by the report
-keepclassmembers class com.incognia.guardapp.detection.SecurityReport {
    public *;
}

# Suppress warnings for reflection-based system property access
-dontwarn android.os.SystemProperties
