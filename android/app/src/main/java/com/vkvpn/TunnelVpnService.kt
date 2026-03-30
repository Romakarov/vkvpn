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
        @Volatile var isRunning = false
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
                val link = intent.getStringExtra("link") ?: ""
                val provider = intent.getStringExtra("provider") ?: "vk"
                val wgPrivKey = intent.getStringExtra("wg_privkey") ?: return START_NOT_STICKY
                val wgAddress = intent.getStringExtra("wg_address") ?: "10.66.66.2"
                val wgDns = intent.getStringExtra("wg_dns") ?: "1.1.1.1"
                val serverPubKey = intent.getStringExtra("wg_pubkey") ?: return START_NOT_STICKY
                val dtlsPort = intent.getIntExtra("dtls_port", 56000)
                val dtlsFingerprint = intent.getStringExtra("dtls_fingerprint") ?: ""
                val turnUser = intent.getStringExtra("turn_username") ?: ""
                val turnPass = intent.getStringExtra("turn_password") ?: ""
                val turnAddr = intent.getStringExtra("turn_address") ?: ""
                val protocol = intent.getStringExtra("protocol") ?: "turn"
                val telemostLink = intent.getStringExtra("telemost_link") ?: ""

                startForeground(1, buildNotification("Connecting..."))
                if (protocol == "vp8" && telemostLink.isNotEmpty()) {
                    startVP8Tunnel(telemostLink, wgPrivKey, wgAddress, wgDns, serverPubKey)
                } else {
                    startTunnel(server, link, provider, wgPrivKey, wgAddress, wgDns, serverPubKey, dtlsPort, dtlsFingerprint, turnUser, turnPass, turnAddr)
                }
            }
            ACTION_STOP -> {
                stopTunnel()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY // don't restart automatically after kill
    }

    private fun startTunnel(
        server: String, link: String, provider: String,
        wgPrivKey: String, wgAddress: String, wgDns: String,
        serverPubKey: String, dtlsPort: Int, dtlsFingerprint: String,
        turnUser: String = "", turnPass: String = "", turnAddr: String = ""
    ) {
        tunnelThread = Thread {
            try {
                val builder = Builder()
                    .setSession("VKVPN")
                    .addAddress(wgAddress, 32)
                    .addRoute("0.0.0.0", 0)       // all IPv4
                    .addRoute("::", 0)              // all IPv6 — prevent leaks
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

                val tunFd = vpnInterface!!.detachFd()
                vpnInterface = null

                val vkLink = if (provider == "vk") link else ""
                val yaLink = if (provider == "yandex") link else ""
                val peerAddr = "$server:$dtlsPort"

                Log.i(TAG, "Starting tunnel to $peerAddr")
                // Enable remote logging to VPS
                Tunnel.setRemoteLog("https://$server:8080", wgAddress)
                if (turnUser.isNotEmpty()) {
                    Log.i(TAG, "Using server-provided TURN credentials")
                    Tunnel.startWithCreds(
                        tunFd.toLong(), peerAddr,
                        vkLink, yaLink,
                        0L, wgPrivKey, serverPubKey,
                        dtlsFingerprint,
                        turnUser, turnPass, turnAddr,
                        "" // telemostLink (VP8 fallback, not used yet)
                    )
                } else {
                    Tunnel.start(
                        tunFd.toLong(), peerAddr,
                        vkLink, yaLink,
                        0L, wgPrivKey, serverPubKey,
                        dtlsFingerprint
                    )
                }

                isRunning = true
                updateNotification("Connected")

                while (isRunning && Tunnel.isRunning()) {
                    Thread.sleep(1000)
                }

                updateNotification("Disconnected")

            } catch (e: Exception) {
                Log.e(TAG, "Tunnel error", e)
            } finally {
                isRunning = false
                try { Tunnel.stop() } catch (_: Exception) {}
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }.also { it.start() }
    }

    private fun startVP8Tunnel(
        telemostLink: String, wgPrivKey: String, wgAddress: String,
        wgDns: String, serverPubKey: String
    ) {
        tunnelThread = Thread {
            try {
                val builder = Builder()
                    .setSession("VKVPN VP8")
                    .addAddress(wgAddress, 32)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .setMtu(1280)
                    .setBlocking(true)

                wgDns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                    builder.addDnsServer(it)
                }
                builder.addDisallowedApplication(packageName)

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN")
                    return@Thread
                }

                val tunFd = vpnInterface!!.detachFd()
                vpnInterface = null

                Log.i(TAG, "Starting VP8/Telemost tunnel")
                Tunnel.startVP8(
                    tunFd.toLong(), telemostLink,
                    wgPrivKey, serverPubKey, wgAddress, wgDns
                )

                isRunning = true
                updateNotification("Connected (VP8)")

                while (isRunning && Tunnel.isRunning()) {
                    Thread.sleep(1000)
                }

                updateNotification("Disconnected")

            } catch (e: Exception) {
                Log.e(TAG, "VP8 tunnel error", e)
            } finally {
                isRunning = false
                try { Tunnel.stop() } catch (_: Exception) {}
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }.also { it.start() }
    }

    private fun stopTunnel() {
        isRunning = false
        try { Tunnel.stop() } catch (_: Exception) {}
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
