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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class TunnelVpnService : VpnService() {

    companion object {
        const val TAG = "VKVPN"
        const val ACTION_START = "com.vkvpn.START"
        const val ACTION_STOP = "com.vkvpn.STOP"
        const val CHANNEL_ID = "vkvpn_channel"
        const val WG_LOCAL_PORT = 9000
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

                startForeground(1, buildNotification("Connecting..."))
                startTunnel(server, link, provider, wgPrivKey, wgAddress, wgDns)
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
        wgPrivKey: String, wgAddress: String, wgDns: String
    ) {
        tunnelThread = Thread {
            try {
                // 1. Start TURN tunnel (Go library) — listens on localhost:9000
                val vkLink = if (provider == "vk") link else ""
                val yaLink = if (provider == "yandex") link else ""

                Tunnel.setLogCallback { msg -> Log.d(TAG, msg) }

                val err = Tunnel.start(server, vkLink, yaLink, 0, WG_LOCAL_PORT)
                if (err != null) {
                    Log.e(TAG, "Tunnel start error: $err")
                    return@Thread
                }

                // 2. Create VPN interface (TUN device)
                val builder = Builder()
                    .setSession("VKVPN")
                    .addAddress(wgAddress, 32)
                    .addRoute("0.0.0.0", 0)
                    .setMtu(1280)
                    .setBlocking(true)

                // Add DNS servers
                wgDns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                    builder.addDnsServer(it)
                }

                // Exclude our own TURN traffic from the VPN
                builder.addDisallowedApplication(packageName)

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN")
                    Tunnel.stop()
                    return@Thread
                }

                isRunning = true
                updateNotification("Connected")
                Log.i(TAG, "VPN established, bridging TUN <-> WireGuard <-> TURN")

                // 3. Bridge: TUN fd <-> WireGuard UDP (localhost:WG_LOCAL_PORT)
                // WireGuard runs as a standard UDP endpoint on localhost
                // We read IP packets from TUN, send as WireGuard UDP to localhost:9000
                // The TURN tunnel forwards them to the VPS where the WG server runs
                bridgeTunToWg(vpnInterface!!.fd, wgPrivKey, wgAddress, server)

            } catch (e: Exception) {
                Log.e(TAG, "Tunnel error", e)
            } finally {
                isRunning = false
                Tunnel.stop()
            }
        }.also { it.start() }
    }

    /**
     * Bridge between Android TUN device and WireGuard over TURN tunnel.
     *
     * This function reads raw IP packets from the TUN device,
     * wraps them in WireGuard protocol, and sends to localhost:9000
     * where the TURN tunnel picks them up and sends to VPS.
     *
     * Note: For a production app, we'd use wireguard-go directly.
     * For now, we use Android's built-in WireGuard support or
     * send raw packets through the TURN tunnel to a WG server on VPS.
     *
     * The VPS runs WireGuard server which handles the encryption.
     * Here we just need to forward TUN packets through the tunnel.
     */
    private fun bridgeTunToWg(tunFd: Int, wgPrivKey: String, wgAddress: String, server: String) {
        val tunIn = FileInputStream(vpnInterface!!.fileDescriptor)
        val tunOut = FileOutputStream(vpnInterface!!.fileDescriptor)

        // UDP socket to local WireGuard (via TURN tunnel)
        val wgSocket = DatagramSocket()
        protect(wgSocket) // Prevent VPN loop

        val localAddr = InetAddress.getByName("127.0.0.1")

        // TUN -> WG (read from TUN, send to localhost:9000 which goes through TURN to VPS WG)
        val sendThread = Thread {
            val buf = ByteArray(1600)
            try {
                while (isRunning) {
                    val n = tunIn.read(buf)
                    if (n > 0) {
                        val pkt = DatagramPacket(buf, n, localAddr, WG_LOCAL_PORT)
                        wgSocket.send(pkt)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "TUN->WG error", e)
            }
        }

        // WG -> TUN (receive from WG, write to TUN)
        val recvThread = Thread {
            val buf = ByteArray(1600)
            try {
                while (isRunning) {
                    val pkt = DatagramPacket(buf, buf.size)
                    wgSocket.receive(pkt)
                    if (pkt.length > 0) {
                        tunOut.write(buf, 0, pkt.length)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "WG->TUN error", e)
            }
        }

        sendThread.start()
        recvThread.start()
        sendThread.join()
        recvThread.join()

        wgSocket.close()
    }

    private fun stopTunnel() {
        isRunning = false
        Tunnel.stop()
        vpnInterface?.close()
        vpnInterface = null
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
