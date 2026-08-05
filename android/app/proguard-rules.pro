# JNA and the UniFFI bindings on top of it are wired together by reflection, so
# R8 cannot see how any of it is used. Everything below either silences a
# desktop-only reference or pins a name the runtime looks up as a string.

# JNA carries desktop code paths (com.sun.jna.Native$AWT) that reference
# java.awt, which does not exist in android.jar. Nothing on Android reaches
# them, so drop the warnings rather than keep dead stubs.
-dontwarn java.awt.**

# JNA itself resolves classes, fields and methods by name at runtime.
-keep class com.sun.jna.** { *; }
# Struct subclasses are marshalled field by field: names and declaration order
# define the native layout, so members must keep both.
-keepclassmembers class * extends com.sun.jna.Structure { *; }
# Callbacks are invoked from native code through their single declared method.
-keep class * implements com.sun.jna.Callback { *; }

# @Structure.FieldOrder is the only record of the order JNA marshals fields in;
# proguard-android-optimize.txt already keeps annotations, but this binding
# breaks silently at runtime if that ever stops being true.
-keepattributes *Annotation*

# UniFFI bindings. UniffiLib/IntegrityCheckingUniffiLib use JNA direct mapping
# (Native.register), which binds each `external` method to the symbol of the
# same name in liboutline_android.so; RustBuffer, ForeignBytes and
# UniffiRustCallStatus are JNA structs. Renaming any of it fails at runtime,
# not at build time.
-keep class uniffi.outline_android.** { *; }
