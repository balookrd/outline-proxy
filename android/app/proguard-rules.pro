# UniFFI bindings call into the native library via JNA; keep their classes.
-keep class uniffi.outline_android.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
