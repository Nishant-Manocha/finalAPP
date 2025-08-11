package com.pankaj465.FinGuard

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object SecurityUtils {
    fun isDeviceRooted(context: Context): Boolean {
        if (Build.TAGS?.contains("test-keys") == true) return true
        val paths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/su",
            "/system/xbin/daemonsu",
            "/su/bin/su"
        )
        if (paths.any { File(it).exists() }) return true
        return canExecuteSu()
    }

    private fun canExecuteSu(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val line = reader.readLine()
            reader.close()
            line != null
        } catch (_: Throwable) {
            false
        }
    }

    fun isEmulator(): Boolean {
        val fingerprint = Build.FINGERPRINT ?: ""
        val model = Build.MODEL ?: ""
        val manufacturer = Build.MANUFACTURER ?: ""
        val brand = Build.BRAND ?: ""
        val device = Build.DEVICE ?: ""
        val product = Build.PRODUCT ?: ""
        return fingerprint.startsWith("generic") ||
                fingerprint.lowercase().contains("vbox") ||
                fingerprint.lowercase().contains("test-keys") ||
                model.contains("google_sdk", true) ||
                model.contains("Emulator", true) ||
                model.contains("Android SDK built for x86", true) ||
                manufacturer.contains("Genymotion", true) ||
                (brand.startsWith("generic") && device.startsWith("generic")) ||
                product == "google_sdk"
    }

    fun isDeveloperModeEnabled(context: Context): Boolean {
        return try {
            val dev = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            ) == 1
            val adb = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED,
                0
            ) == 1
            dev || adb
        } catch (_: Throwable) {
            false
        }
    }
}