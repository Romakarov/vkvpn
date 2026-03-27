package com.vkvpn

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import android.os.Environment
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanIntentResult
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    companion object {
        const val VPN_REQUEST_CODE = 1
        const val CAMERA_PERMISSION_CODE = 2
        const val PREFS = "vkvpn_prefs_encrypted"
    }

    private fun getEncryptedPrefs(): SharedPreferences {
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            this, PREFS, masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private lateinit var mainScreen: View
    private lateinit var setupScreen: View
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvClientName: TextView
    private lateinit var btnReset: Button
    private lateinit var etConfig: EditText
    private lateinit var btnImport: Button
    private lateinit var btnScanQr: Button
    private lateinit var btnLogs: Button
    private lateinit var logViewer: View
    private lateinit var logButtons: View
    private lateinit var tvLogs: TextView
    private lateinit var btnCopyLogs: Button
    private lateinit var btnSaveLogs: Button
    private lateinit var btnRefreshLogs: Button

    // QR scanner launcher
    private val qrLauncher = registerForActivityResult(ScanContract()) { result: ScanIntentResult ->
        if (result.contents != null) {
            processConfig(result.contents)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        mainScreen = findViewById(R.id.main_screen)
        setupScreen = findViewById(R.id.setup_screen)
        btnConnect = findViewById(R.id.btn_connect)
        tvStatus = findViewById(R.id.tv_status)
        tvClientName = findViewById(R.id.tv_client_name)
        btnReset = findViewById(R.id.btn_reset)
        etConfig = findViewById(R.id.et_config)
        btnImport = findViewById(R.id.btn_import)
        btnScanQr = findViewById(R.id.btn_scan_qr)
        btnLogs = findViewById(R.id.btn_logs)
        logViewer = findViewById(R.id.log_viewer)
        logButtons = findViewById(R.id.log_buttons)
        tvLogs = findViewById(R.id.tv_logs)
        btnCopyLogs = findViewById(R.id.btn_copy_logs)
        btnSaveLogs = findViewById(R.id.btn_save_logs)
        btnRefreshLogs = findViewById(R.id.btn_refresh_logs)

        btnConnect.setOnClickListener {
            if (TunnelVpnService.isRunning) {
                stopVpn()
            } else {
                startVpn()
            }
        }

        btnImport.setOnClickListener {
            val text = etConfig.text.toString().trim()
            if (text.isEmpty()) {
                Toast.makeText(this, "Paste config JSON", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            processConfig(text)
        }

        btnScanQr.setOnClickListener {
            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(Manifest.permission.CAMERA), CAMERA_PERMISSION_CODE)
            } else {
                launchQrScanner()
            }
        }

        btnLogs.setOnClickListener { toggleLogs() }
        btnCopyLogs.setOnClickListener { copyLogs() }
        btnSaveLogs.setOnClickListener { saveLogs() }
        btnRefreshLogs.setOnClickListener { refreshLogs() }

        btnReset.setOnClickListener {
            if (TunnelVpnService.isRunning) {
                stopVpn()
            }
            getEncryptedPrefs().edit().clear().apply()
            showScreen()
        }

        showScreen()
    }

    override fun onResume() {
        super.onResume()
        updateUI()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_CODE && grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            launchQrScanner()
        } else if (requestCode == CAMERA_PERMISSION_CODE) {
            Toast.makeText(this, "Camera permission required to scan QR", Toast.LENGTH_LONG).show()
        }
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Scan config QR from admin panel")
            setBeepEnabled(false)
            setOrientationLocked(true)
            setCameraId(0)
        }
        qrLauncher.launch(options)
    }

    private fun processConfig(text: String) {
        try {
            val json = JSONObject(text)
            val prefs = getEncryptedPrefs().edit()
            prefs.putString("server", json.getString("server"))
            prefs.putString("link", json.optString("link", ""))
            prefs.putString("provider", json.optString("provider", "vk"))
            prefs.putString("wg_privkey", json.getString("wg_privkey"))
            prefs.putString("wg_address", json.optString("wg_address", "10.66.66.2"))
            prefs.putString("wg_dns", json.optString("wg_dns", "1.1.1.1"))
            prefs.putString("wg_pubkey", json.getString("wg_pubkey"))
            prefs.putInt("dtls_port", json.optInt("dtls_port", 56000))
            prefs.putString("dtls_fingerprint", json.optString("dtls_fingerprint", ""))
            prefs.putString("name", json.optString("name", ""))
            // Server-provided TURN credentials (optional)
            prefs.putString("turn_username", json.optString("turn_username", ""))
            prefs.putString("turn_password", json.optString("turn_password", ""))
            prefs.putString("turn_address", json.optString("turn_address", ""))
            prefs.apply()

            Toast.makeText(this, "Config imported! ✓", Toast.LENGTH_SHORT).show()
            showScreen()
        } catch (e: Exception) {
            Toast.makeText(this, "Invalid config: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun hasConfig(): Boolean {
        val prefs = getEncryptedPrefs()
        return prefs.getString("server", "")?.isNotEmpty() == true &&
               prefs.getString("wg_privkey", "")?.isNotEmpty() == true &&
               prefs.getString("wg_pubkey", "")?.isNotEmpty() == true
    }

    private fun showScreen() {
        if (hasConfig()) {
            mainScreen.visibility = View.VISIBLE
            setupScreen.visibility = View.GONE
            val prefs = getEncryptedPrefs()
            tvClientName.text = prefs.getString("name", "")
        } else {
            mainScreen.visibility = View.GONE
            setupScreen.visibility = View.VISIBLE
        }
        updateUI()
    }

    private fun updateUI() {
        if (TunnelVpnService.isRunning) {
            btnConnect.text = "Disconnect"
            btnConnect.setBackgroundResource(R.drawable.btn_circle_active)
            tvStatus.text = "Connected"
            tvStatus.setTextColor(0xFF00B894.toInt())
        } else {
            btnConnect.text = "Connect"
            btnConnect.setBackgroundResource(R.drawable.btn_circle)
            tvStatus.text = "Disconnected"
            tvStatus.setTextColor(0xFFFF6B6B.toInt())
        }
    }

    private fun startVpn() {
        val prefs = getEncryptedPrefs()
        val server = prefs.getString("server", "") ?: ""
        val link = prefs.getString("link", "") ?: ""
        val wgPrivKey = prefs.getString("wg_privkey", "") ?: ""

        if (server.isEmpty() || wgPrivKey.isEmpty()) {
            Toast.makeText(this, "Config incomplete", Toast.LENGTH_SHORT).show()
            return
        }

        if (link.isEmpty()) {
            Toast.makeText(this, "No TURN link configured. Ask your admin.", Toast.LENGTH_LONG).show()
            return
        }

        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            launchVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            launchVpn()
        }
    }

    private fun launchVpn() {
        val prefs = getEncryptedPrefs()
        val intent = Intent(this, TunnelVpnService::class.java).apply {
            action = TunnelVpnService.ACTION_START
            putExtra("server", prefs.getString("server", ""))
            putExtra("link", prefs.getString("link", ""))
            putExtra("provider", prefs.getString("provider", "vk"))
            putExtra("wg_privkey", prefs.getString("wg_privkey", ""))
            putExtra("wg_address", prefs.getString("wg_address", "10.66.66.2"))
            putExtra("wg_dns", prefs.getString("wg_dns", "1.1.1.1"))
            putExtra("wg_pubkey", prefs.getString("wg_pubkey", ""))
            putExtra("dtls_port", prefs.getInt("dtls_port", 56000))
            putExtra("dtls_fingerprint", prefs.getString("dtls_fingerprint", ""))
            putExtra("turn_username", prefs.getString("turn_username", ""))
            putExtra("turn_password", prefs.getString("turn_password", ""))
            putExtra("turn_address", prefs.getString("turn_address", ""))
        }
        startForegroundService(intent)
        Toast.makeText(this, "Connecting...", Toast.LENGTH_SHORT).show()
        btnConnect.postDelayed({ updateUI() }, 2000)
    }

    private fun stopVpn() {
        val intent = Intent(this, TunnelVpnService::class.java).apply {
            action = TunnelVpnService.ACTION_STOP
        }
        startService(intent)
        btnConnect.postDelayed({ updateUI() }, 1000)
    }

    // ─── Log Viewer ───

    private var logsVisible = false

    private fun toggleLogs() {
        logsVisible = !logsVisible
        if (logsVisible) {
            logViewer.visibility = View.VISIBLE
            logButtons.visibility = View.VISIBLE
            refreshLogs()
        } else {
            logViewer.visibility = View.GONE
            logButtons.visibility = View.GONE
        }
    }

    private fun refreshLogs() {
        try {
            val logsJson = tunnel.Tunnel.getLogs()
            val arr = org.json.JSONArray(logsJson)
            val sb = StringBuilder()
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                val time = e.optString("time", "")
                val level = e.optString("level", "info")
                val msg = e.optString("message", "")
                val prefix = if (level == "error") "❌" else "•"
                sb.append("$time $prefix $msg\n")
            }
            tvLogs.text = if (sb.isEmpty()) "No logs yet. Connect to see tunnel activity." else sb.toString()
        } catch (e: Exception) {
            tvLogs.text = "Error reading logs: ${e.message}"
        }
    }

    private fun copyLogs() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("VKVPN Logs", tvLogs.text))
        Toast.makeText(this, "Logs copied!", Toast.LENGTH_SHORT).show()
    }

    private fun saveLogs() {
        try {
            val dir = getExternalFilesDir(null) ?: filesDir
            val file = java.io.File(dir, "vkvpn-logs-${System.currentTimeMillis()}.txt")
            file.writeText(tvLogs.text.toString())
            Toast.makeText(this, "Saved: ${file.name}", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Save error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
