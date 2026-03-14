package com.vkvpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.*
import org.json.JSONObject

class MainActivity : Activity() {

    companion object {
        const val VPN_REQUEST_CODE = 1
        const val PREFS = "vkvpn_prefs"
    }

    private lateinit var mainScreen: View
    private lateinit var setupScreen: View
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvClientName: TextView
    private lateinit var btnReset: Button
    private lateinit var etConfig: EditText
    private lateinit var btnImport: Button

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

        btnConnect.setOnClickListener {
            if (TunnelVpnService.isRunning) {
                stopVpn()
            } else {
                startVpn()
            }
        }

        btnImport.setOnClickListener {
            importConfig()
        }

        btnReset.setOnClickListener {
            if (TunnelVpnService.isRunning) {
                stopVpn()
            }
            getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
            showScreen()
        }

        showScreen()
    }

    override fun onResume() {
        super.onResume()
        updateUI()
    }

    private fun hasConfig(): Boolean {
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.getString("server", "")?.isNotEmpty() == true &&
               prefs.getString("wg_privkey", "")?.isNotEmpty() == true
    }

    private fun showScreen() {
        if (hasConfig()) {
            mainScreen.visibility = View.VISIBLE
            setupScreen.visibility = View.GONE
            val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            tvClientName.text = prefs.getString("name", "")
        } else {
            mainScreen.visibility = View.GONE
            setupScreen.visibility = View.VISIBLE
        }
        updateUI()
    }

    private fun importConfig() {
        val text = etConfig.text.toString().trim()
        if (text.isEmpty()) {
            Toast.makeText(this, "Paste config JSON", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            val json = JSONObject(text)
            val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            prefs.putString("server", json.getString("server"))
            prefs.putString("link", json.optString("link", ""))
            prefs.putString("provider", json.optString("provider", "vk"))
            prefs.putString("wg_privkey", json.getString("wg_privkey"))
            prefs.putString("wg_address", json.optString("wg_address", "10.66.66.2"))
            prefs.putString("wg_dns", json.optString("wg_dns", "1.1.1.1"))
            prefs.putString("name", json.optString("name", ""))
            prefs.apply()

            Toast.makeText(this, "Config imported!", Toast.LENGTH_SHORT).show()
            showScreen()
        } catch (e: Exception) {
            Toast.makeText(this, "Invalid config: ${e.message}", Toast.LENGTH_LONG).show()
        }
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
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
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
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val intent = Intent(this, TunnelVpnService::class.java).apply {
            action = TunnelVpnService.ACTION_START
            putExtra("server", prefs.getString("server", ""))
            putExtra("link", prefs.getString("link", ""))
            putExtra("provider", prefs.getString("provider", "vk"))
            putExtra("wg_privkey", prefs.getString("wg_privkey", ""))
            putExtra("wg_address", prefs.getString("wg_address", "10.66.66.2"))
            putExtra("wg_dns", prefs.getString("wg_dns", "1.1.1.1"))
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
}
