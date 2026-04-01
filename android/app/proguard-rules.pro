# Keep Go mobile bindings
-keep class tunnel.** { *; }
-keep class go.** { *; }

# Keep VPN service
-keep class com.vkvpn.TunnelVpnService { *; }

# Suppress missing annotation warnings (from Tink/crypto deps)
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.CheckReturnValue
-dontwarn com.google.errorprone.annotations.Immutable
-dontwarn com.google.errorprone.annotations.RestrictedApi
