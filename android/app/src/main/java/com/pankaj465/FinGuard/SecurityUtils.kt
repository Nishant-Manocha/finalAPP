package com.pankaj465.FinGuard

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object SecurityUtils {

    fun isDeviceRooted(): Boolean {
        // Check for test-keys in build tags
        if (Build.TAGS?.contains("test-keys") == true) return true

        // Check common SU paths
        val suPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
            "/system/etc/.has_su_daemon",
            "/system/etc/.installed_su_daemon",
            "/system/xbin/supolicy",
            "/system/bin/supolicy"
        )
        if (suPaths.any { File(it).exists() }) return true

        // Try executing which su
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            result != null
        } catch (_: Exception) {
            false
        }
    }

    fun isRunningOnEmulator(): Boolean {
        val product = Build.PRODUCT?.lowercase() ?: ""
        val fingerprint = Build.FINGERPRINT?.lowercase() ?: ""
        val manufacturer = Build.MANUFACTURER?.lowercase() ?: ""
        val brand = Build.BRAND?.lowercase() ?: ""
        val device = Build.DEVICE?.lowercase() ?: ""
        val model = Build.MODEL?.lowercase() ?: ""

        if (fingerprint.startsWith("generic") || fingerprint.contains("emulator")) return true
        if (model.contains("google_sdk") || model.contains("emulator") || model.contains("android sdk built for x86")) return true
        if (manufacturer.contains("genymotion")) return true
        if (brand.startsWith("generic") && device.startsWith("generic")) return true
        if (product == "google_sdk") return true

        return false
    }

    fun isDeveloperOptionsEnabled(context: Context): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }
    }

    fun isAdbEnabled(context: Context): Boolean {
        return try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }
    }

    fun shouldBlockApp(context: Context): Boolean {
        if (BuildConfig.BLOCK_ON_ROOT && isDeviceRooted()) return true
        if (BuildConfig.BLOCK_ON_EMULATOR && isRunningOnEmulator()) return true
        if (BuildConfig.BLOCK_ON_DEVELOPER_OPTIONS && (isDeveloperOptionsEnabled(context) || isAdbEnabled(context))) return true
        return false
    }
}