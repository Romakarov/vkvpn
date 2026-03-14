package com.vkvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import tunnel.Tunnel

class TunnelVpnService : VpnService() {

    companion object {
        const val TAG = "VKVPN"
        const val ACTION_START = "com.vkvpn.START"
        const val ACTION_STOP = "com.vkvpn.STOP"
        const val CHANNEL_ID = "vkvpn_channel"
        var isRunning = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val server = intent.getStringExtra("server") ?: return START_NOT_STICKY
                val link = intent.getStringExtra("link") ?: return START_NOT_STICKY
                val provider = intent.getStringExtra("provider") ?: "vk"
                val wgPrivKey = intent.getStringExtra("wg_privkey") ?: return START_NOT_STICKY
                val wgAddress = intent.getStringExtra("wg_address") ?: "10.66.66.2"
                val wgDns = intent.getStringExtra("wg_dns") ?: "1.1.1.1"
                val serverPubKey = intent.getStringExtra("wg_pubkey") ?: return START_NOT_STICKY
                val dtlsPort = intent.getIntExtra("dtls_port", 56000)

                startForeground(1, buildNotification("Connecting..."))
                startTunnel(server, link, provider, wgPrivKey, wgAddress, wgDns, serverPubKey, dtlsPort)
            }
            ACTION_STOP -> {
                stopTunnel()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun startTunnel(
        server: String, link: String, provider: String,
        wgPrivKey: String, wgAddress: String, wgDns: String,
        serverPubKey: String, dtlsPort: Int
    ) {
        tunnelThread = Thread {
            try {
                // 1. Create VPN interface (TUN device) FIRST
                val builder = Builder()
                    .setSession("VKVPN")
                    .addAddress(wgAddress, 32)
                    .addRoute("0.0.0.0", 0)
                    .setMtu(1280)
                    .setBlocking(true)

                wgDns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                    builder.addDnsServer(it)
                }

                // Exclude our own app so TURN traffic bypasses VPN
                builder.addDisallowedApplication(packageName)

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN")
                    return@Thread
                }

                // 2. Detach fd — Go/wireguard-go now owns the TUN device
                val tunFd = vpnInterface!!.detachFd()
                vpnInterface = null

                isRunning = true
                updateNotification("Connected")

                // 3. Start tunnel: wireguard-go reads TUN fd, encrypts,
                //    DTLS+TURN forwards to server
                val vkLink = if (provider == "vk") link else ""
                val yaLink = if (provider == "yandex") link else ""
                val peerAddr = "$server:$dtlsPort"

                Log.i(TAG, "Starting tunnel to $peerAddr")
                Tunnel.start(
                    tunFd.toLong(), peerAddr,
                    vkLink, yaLink,
                    0L, wgPrivKey, serverPubKey
                )

                // Tunnel.start() returns immediately; wait until stopped
                while (isRunning && Tunnel.isRunning()) {
                    Thread.sleep(1000)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Tunnel error", e)
            } finally {
                isRunning = false
                Tunnel.stop()
            }
        }.also { it.start() }
    }

    private fun stopTunnel() {
        isRunning = false
        Tunnel.stop()
        // vpnInterface is null after detachFd — fd is closed by Go
        tunnelThread?.interrupt()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "VKVPN Tunnel",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("VKVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            ?.notify(1, buildNotification(text))
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
