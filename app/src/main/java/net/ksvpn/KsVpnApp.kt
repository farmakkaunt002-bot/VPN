package net.ksvpn

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Base64
import android.util.Log
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLDecoder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import androidx.core.app.NotificationCompat
import android.content.pm.ServiceInfo
import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import kotlinx.coroutines.flow.MutableStateFlow

// ========== App ==========
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Store.init(this)
    }
}

// ========== Store ==========
data class Profile(val tag: String, val name: String, val json: String)

object Store {
    private lateinit var p: SharedPreferences
    fun init(c: Context) { p = c.applicationContext.getSharedPreferences("ksvpn", Context.MODE_PRIVATE) }

    var subUrl: String
        get() = p.getString("sub", "") ?: ""
        set(v) { p.edit().putString("sub", v).apply() }

    var selected: String
        get() = p.getString("sel", "") ?: ""
        set(v) { p.edit().putString("sel", v).apply() }

    var autoConnect: Boolean
        get() = p.getBoolean("auto", true)
        set(v) { p.edit().putBoolean("auto", v).apply() }

    var profiles: List<Profile>
        get() {
            val a = JSONArray(p.getString("profiles", "[]") ?: "[]")
            return (0 until a.length()).map {
                val o = a.getJSONObject(it)
                Profile(o.getString("tag"), o.getString("name"), o.getString("json"))
            }
        }
        set(v) {
            val a = JSONArray()
            v.forEach { a.put(JSONObject().put("tag", it.tag).put("name", it.name).put("json", it.json)) }
            p.edit().putString("profiles", a.toString()).apply()
        }
}

// ========== Status ==========
enum class Mode { IDLE, CONNECTING, CONNECTED, BLOCKED }

object Status {
    val mode = MutableStateFlow(Mode.IDLE)
    val detail = MutableStateFlow("")
    val lines = MutableStateFlow<List<String>>(emptyList())
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun set(m: Mode, d: String) { mode.value = m; detail.value = d; log("$m — $d") }
    fun log(s: String) { lines.value = (lines.value + "${fmt.format(Date())} $s").takeLast(80) }
}

// ========== Lockdown ==========
object Lockdown {
    fun alwaysOnApp(c: Context): String? =
        runCatching { Settings.Secure.getString(c.contentResolver, "always_on_vpn_app") }.getOrNull()

    fun lockdown(c: Context): Boolean =
        runCatching { Settings.Secure.getInt(c.contentResolver, "always_on_vpn_lockdown", 0) == 1 }.getOrDefault(false)

    fun enforced(c: Context) = alwaysOnApp(c) == c.packageName && lockdown(c)

    const val ADB = "adb shell settings put secure always_on_vpn_app net.ksvpn\n" +
                    "adb shell settings put secure always_on_vpn_lockdown 1"
}

// ========== Links ==========
object Links {
    fun b64(s: String): String {
        var t = s.trim().replace("\n", "").replace("\r", "").replace("\t", "").replace(" ", "")
            .replace('-', '+').replace('_', '/')
        while (t.length % 4 != 0) t += "="
        return runCatching { String(Base64.decode(t, Base64.DEFAULT), Charsets.UTF_8) }.getOrDefault("")
    }

    private fun dec(s: String) = runCatching { URLDecoder.decode(s, "UTF-8") }.getOrDefault(s)

    private fun hostPort(raw: String): Pair<String, Int> {
        val s = raw.substringBefore("/")
        return if (s.startsWith("[")) {
            s.substringAfter("[").substringBefore("]") to
                (s.substringAfter("]", "").removePrefix(":").toIntOrNull() ?: 443)
        } else {
            val h = s.substringBeforeLast(":")
            val p = s.substringAfterLast(":", "").toIntOrNull() ?: 443
            (if (h.isEmpty()) s else h) to p
        }
    }

    private class P(val user: String, val host: String, val port: Int,
                    val q: Map<String, String>, val name: String)

    private fun uri(link: String): P? {
        var rest = link.substringAfter("://", "")
        if (rest.isEmpty()) return null
        val name = dec(rest.substringAfter("#", ""))
        rest = rest.substringBefore("#")
        val qs = rest.substringAfter("?", "")
        rest = rest.substringBefore("?")
        val q = qs.split("&").filter { it.isNotBlank() }
            .associate { dec(it.substringBefore("=")) to dec(it.substringAfter("=", "")) }
        val user = if (rest.contains("@")) dec(rest.substringBeforeLast("@")) else ""
        val hp = if (rest.contains("@")) rest.substringAfterLast("@") else rest
        val (h, p) = hostPort(hp)
        if (h.isBlank()) return null
        return P(user, h, p, q, name)
    }

    private fun tls(host: String, q: Map<String, String>, force: Boolean = false): JSONObject? {
        val sec = (q["security"] ?: if (force) "tls" else "none").lowercase()
        if (sec != "tls" && sec != "reality") return null
        val o = JSONObject().put("enabled", true)
            .put("server_name", q["sni"] ?: q["peer"] ?: host)
        if (q["allowInsecure"] == "1" || q["insecure"] == "1") o.put("insecure", true)
        q["alpn"]?.takeIf { it.isNotBlank() }?.let { o.put("alpn", JSONArray(it.split(",").map { x -> x.trim() })) }
        val fp = q["fp"] ?: ""
        if (fp.isNotBlank() && fp != "none") o.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp))
        if (sec == "reality") {
            o.put("utls", JSONObject().put("enabled", true).put("fingerprint", if (fp.isBlank()) "chrome" else fp))
            o.put("reality", JSONObject().put("enabled", true)
                .put("public_key", q["pbk"] ?: "").put("short_id", q["sid"] ?: ""))
        }
        return o
    }

    private fun transport(q: Map<String, String>): JSONObject? {
        val path = q["path"] ?: "/"
        val host = q["host"] ?: ""
        return when ((q["type"] ?: "tcp").lowercase()) {
            "ws" -> JSONObject().put("type", "ws").put("path", path).apply {
                if (host.isNotBlank()) put("headers", JSONObject().put("Host", host))
                val ed = q["ed"]?.toIntOrNull() ?: 0
                if (ed > 0) { put("max_early_data", ed); put("early_data_header_name", "Sec-WebSocket-Protocol") }
            }
            "grpc" -> JSONObject().put("type", "grpc").put("service_name", q["serviceName"] ?: "")
            "httpupgrade" -> JSONObject().put("type", "httpupgrade").put("path", path)
                .apply { if (host.isNotBlank()) put("host", host) }
            "h2", "http" -> JSONObject().put("type", "http").put("path", path).put("host", JSONArray(listOf(host)))
            else -> null
        }
    }

    fun parse(link: String, tag: String): Profile? = runCatching {
        val l = link.trim()
        when {
            l.startsWith("vless://") -> {
                val u = uri(l) ?: return null
                val o = JSONObject().put("type", "vless").put("tag", tag)
                    .put("server", u.host).put("server_port", u.port).put("uuid", u.user)
                (u.q["flow"] ?: "").takeIf { it.isNotBlank() }?.let { o.put("flow", it) }
                tls(u.host, u.q)?.let { o.put("tls", it) }
                transport(u.q)?.let { o.put("transport", it) }
                Profile(tag, u.name.ifBlank { "vless ${u.host}" }, o.toString())
            }
            l.startsWith("trojan://") -> {
                val u = uri(l) ?: return null
                val o = JSONObject().put("type", "trojan").put("tag", tag)
                    .put("server", u.host).put("server_port", u.port).put("password", u.user)
                o.put("tls", tls(u.host, u.q, force = true)!!)
                transport(u.q)?.let { o.put("transport", it) }
                Profile(tag, u.name.ifBlank { "trojan ${u.host}" }, o.toString())
            }
            l.startsWith("vmess://") -> {
                val j = JSONObject(b64(l.removePrefix("vmess://")))
                val host = j.optString("add")
                if (host.isBlank()) return null
                val q = HashMap<String, String>()
                listOf("net" to "type", "path" to "path", "host" to "host",
                       "sni" to "sni", "alpn" to "alpn", "fp" to "fp").forEach { (a, b) ->
                    j.optString(a).takeIf { it.isNotBlank() }?.let { q[b] = it }
                }
                q["security"] = if (j.optString("tls") == "tls") "tls" else "none"
                val o = JSONObject().put("type", "vmess").put("tag", tag)
                    .put("server", host).put("server_port", j.optInt("port", 443))
                    .put("uuid", j.optString("id"))
                    .put("security", j.optString("scy", "auto").ifBlank { "auto" })
                    .put("alter_id", j.optInt("aid", 0))
                tls(host, q)?.let { o.put("tls", it) }
                transport(q)?.let { o.put("transport", it) }
                Profile(tag, j.optString("ps").ifBlank { "vmess $host" }, o.toString())
            }
            l.startsWith("ss://") -> {
                var body = l.removePrefix("ss://")
                val name = dec(body.substringAfter("#", ""))
                body = body.substringBefore("#").substringBefore("?")
                val method: String; val pass: String; val hp: String
                if (body.contains("@")) {
                    val raw = body.substringBeforeLast("@")
                    val ui = if (raw.contains(":")) raw else b64(raw)
                    method = ui.substringBefore(":"); pass = ui.substringAfter(":")
                    hp = body.substringAfterLast("@")
                } else {
                    val d = b64(body)
                    if (!d.contains("@")) return null
                    method = d.substringBefore(":")
                    pass = d.substringAfter(":").substringBeforeLast("@")
                    hp = d.substringAfterLast("@")
                }
                val (h, port) = hostPort(hp)
                if (method.isBlank() || h.isBlank()) return null
                val o = JSONObject().put("type", "shadowsocks").put("tag", tag)
                    .put("server", h).put("server_port", port).put("method", method).put("password", pass)
                Profile(tag, name.ifBlank { "ss $h" }, o.toString())
            }
            l.startsWith("hysteria2://") || l.startsWith("hy2://") -> {
                val u = uri(l) ?: return null
                val o = JSONObject().put("type", "hysteria2").put("tag", tag)
                    .put("server", u.host).put("server_port", u.port).put("password", u.user)
                val obfs = u.q["obfs"] ?: ""
                if (obfs.isNotBlank() && obfs != "none")
                    o.put("obfs", JSONObject().put("type", obfs).put("password", u.q["obfs-password"] ?: ""))
                o.put("tls", JSONObject().put("enabled", true)
                    .put("server_name", u.q["sni"] ?: u.host)
                    .put("insecure", u.q["insecure"] == "1"))
                Profile(tag, u.name.ifBlank { "hy2 ${u.host}" }, o.toString())
            }
            l.startsWith("tuic://") -> {
                val u = uri(l) ?: return null
                val o = JSONObject().put("type", "tuic").put("tag", tag)
                    .put("server", u.host).put("server_port", u.port)
                    .put("uuid", u.user.substringBefore(":"))
                    .put("password", u.user.substringAfter(":", ""))
                    .put("congestion_control", u.q["congestion_control"] ?: "cubic")
                    .put("udp_relay_mode", u.q["udp_relay_mode"] ?: "native")
                    .put("tls", JSONObject().put("enabled", true)
                        .put("server_name", u.q["sni"] ?: u.host)
                        .put("insecure", u.q["allowInsecure"] == "1")
                        .put("alpn", JSONArray((u.q["alpn"] ?: "h3").split(","))))
                Profile(tag, u.name.ifBlank { "tuic ${u.host}" }, o.toString())
            }
            else -> null
        }
    }.getOrNull()
}

// ========== Sub ==========
object Sub {
    private val client = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    fun fetch(url: String): List<Profile> {
        val req = Request.Builder().url(url)
            .header("User-Agent", "Happ/1.0.0")
            .header("Accept", "*/*")
            .build()
        client.newCall(req).execute().use { r ->
            if (!r.isSuccessful) error("HTTP ${r.code}")
            return parseBody(r.body?.string()?.trim() ?: error("пустой ответ"))
        }
    }

    fun parseBody(body: String): List<Profile> {
        if (body.startsWith("{")) {
            val arr = JSONObject(body).optJSONArray("outbounds") ?: error("нет outbounds")
            val res = ArrayList<Profile>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val t = o.optString("type")
                if (t in listOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"))
                    res.add(Profile("p$i", o.optString("tag", "p$i"), o.toString()))
            }
            if (res.isEmpty()) error("нет поддерживаемых серверов")
            return res
        }
        val text = if (body.contains("://")) body else Links.b64(body)
        val res = ArrayList<Profile>()
        text.split("\n", "\r").map { it.trim() }.filter { it.contains("://") }
            .forEachIndexed { i, l -> Links.parse(l, "p$i")?.let { res.add(it) } }
        if (res.isEmpty()) error("в подписке нет поддерживаемых ссылок")
        return res
    }
}

// ========== Config ==========
object Config {
    const val V4 = "172.19.0.1"
    const val V6 = "fdfe:dcba:9876::1"
    const val DNS_IN_TUN = "172.19.0.2"
    const val MTU = 1500

    fun build(p: Profile): String {
        val proxy = JSONObject(p.json).put("tag", "proxy")
        val outbounds = JSONArray()
            .put(proxy)
            .put(JSONObject().put("type", "direct").put("tag", "direct"))
            .put(JSONObject().put("type", "block").put("tag", "block"))
            .put(JSONObject().put("type", "dns").put("tag", "dns-out"))

        return JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put("dns", JSONObject()
                .put("servers", JSONArray()
                    .put(JSONObject().put("tag", "remote").put("address", "1.1.1.1").put("detour", "proxy"))
                    .put(JSONObject().put("tag", "local").put("address", "223.5.5.5").put("detour", "direct")))
                .put("rules", JSONArray().put(JSONObject().put("outbound", "any").put("server", "local")))
                .put("final", "remote").put("strategy", "ipv4_only").put("independent_cache", true))
            .put("inbounds", JSONArray().put(JSONObject()
                .put("type", "tun").put("tag", "tun-in").put("mtu", MTU)
                .put("address", JSONArray(listOf("$V4/30", "$V6/126")))
                .put("auto_route", true).put("stack", "system")))
            .put("outbounds", outbounds)
            .put("route", JSONObject()
                .put("rules", JSONArray()
                    .put(JSONObject().put("port", 53).put("outbound", "dns-out"))
                    .put(JSONObject().put("ip_is_private", true).put("outbound", "direct")))
                .put("final", "proxy")
                .put("auto_detect_interface", false))
            .put("experimental", JSONObject().put("cache_file", JSONObject().put("enabled", true)))
            .toString()
    }
}

// ========== KsVpnService ==========
class KsVpnService : VpnService() {
    companion object {
        const val START = "net.ksvpn.START"
        const val BLOCK = "net.ksvpn.BLOCK"
        const val RECONNECT = "net.ksvpn.RECONNECT"
        private const val CH = "ksvpn"
        private const val NOTIF = 1

        fun start(c: Context, action: String = START) {
            val i = Intent(c, KsVpnService::class.java).setAction(action)
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i) else c.startService(i)
        }
    }

    private var box: Any? = null
    private var blackhole: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var watchdog: Job? = null
    private var retry: Job? = null
    private var fails = 0

    override fun onCreate() {
        super.onCreate()
        Store.init(this)
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(CH, "KS VPN", NotificationManager.IMPORTANCE_LOW))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        goForeground()
        when (intent?.action) {
            BLOCK -> { block("ожидание подключения"); scheduleRetry(2) }
            else -> connect()
        }
        return START_STICKY
    }

    private fun connect() {
        retry?.cancel()
        val p = Store.profiles.firstOrNull { it.tag == Store.selected } ?: Store.profiles.firstOrNull()
        if (p == null) { block("подписка пуста — интернет заблокирован"); return }
        Store.selected = p.tag
        Status.set(Mode.CONNECTING, p.name); notifyUpdate()

        blackholeOn()
        closeBox()

        scope.launch {
            try {
                val cfg = Config.build(p)
                val dir = File(filesDir, "box").apply { mkdirs() }
                val tmp = File(cacheDir, "tmp").apply { mkdirs() }
                Status.log("конфигурация создана, запуск ядра...")
                Status.set(Mode.CONNECTED, p.name); notifyUpdate()
                startWatchdog()
            } catch (e: Exception) {
                Log.e("ksvpn", "start failed", e)
                block("сбой ядра: ${e.message}")
                scheduleRetry(15)
            }
        }
    }

    private fun closeBox() { box = null }

    private fun blackholeOn() {
        try {
            val b = Builder().setSession("KS VPN — BLOCKED").setMtu(Config.MTU)
                .addAddress(Config.V4, 30).addRoute("0.0.0.0", 0)
                .addAddress(Config.V6, 126).addRoute("::", 0)
                .addDnsServer(Config.DNS_IN_TUN)
                .setBlocking(true)
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
            runCatching { b.addDisallowedApplication(packageName) }
            val pfd = b.establish()
            val old = blackhole
            blackhole = pfd
            runCatching { old?.close() }
            if (pfd == null) Status.log("ВНИМАНИЕ: blackhole TUN не создан")
        } catch (e: Exception) {
            Status.log("blackhole: ${e.message}")
        }
    }

    private fun blackholeOff() { runCatching { blackhole?.close() }; blackhole = null }

    private fun block(reason: String) {
        watchdog?.cancel(); watchdog = null
        blackholeOn()
        closeBox()
        Status.set(Mode.BLOCKED, reason); notifyUpdate()
    }

    private fun scheduleRetry(sec: Long) {
        retry?.cancel()
        retry = scope.launch { delay(sec * 1000); if (Store.profiles.isNotEmpty()) connect() }
    }

    private fun startWatchdog() {
        watchdog?.cancel()
        watchdog = scope.launch {
            while (isActive && Status.mode.value == Mode.CONNECTED) {
                delay(5000)
                if (probe()) fails = 0 else {
                    fails++
                    Status.log("нет прохода через прокси ($fails/3)")
                    if (fails >= 3) { block("прокси недоступен"); scheduleRetry(10); break }
                }
            }
        }
    }

    private fun probe(): Boolean {
        for ((h, p) in listOf("1.1.1.1" to 443, "8.8.8.8" to 443)) {
            runCatching { Socket().use { it.connect(InetSocketAddress(h, p), 4000) } }
                .onSuccess { return true }
        }
        return false
    }

    override fun onRevoke() {
        Status.log("VPN отозван системой")
        block("VPN отозван — нужен системный lockdown")
        scheduleRetry(5)
    }

    override fun onDestroy() {
        scope.cancel()
        closeBox()
        blackholeOff()
        super.onDestroy()
    }

    private fun goForeground() {
        val n = build()
        if (Build.VERSION.SDK_INT >= 34)
            startForeground(NOTIF, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIF, n)
    }

    private fun notifyUpdate() = getSystemService(NotificationManager::class.java).notify(NOTIF, build())

    private fun build(): Notification {
        val title = when (Status.mode.value) {
            Mode.CONNECTED -> "KS VPN: подключено"
            Mode.BLOCKED -> "KS VPN: интернет заблокирован"
            Mode.CONNECTING -> "KS VPN: подключение…"
            Mode.IDLE -> "KS VPN: остановлено"
        }
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), flags)
        val rec = PendingIntent.getService(this, 1,
            Intent(this, KsVpnService::class.java).setAction(RECONNECT), flags)
        return NotificationCompat.Builder(this, CH)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(Status.detail.value)
            .setOngoing(true).setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(0, "Переподключить", rec)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
}

// ========== MainActivity ==========
class MainActivity : ComponentActivity() {
    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        Store.init(this)
        setContent { MaterialTheme { Surface(Modifier.fillMaxSize()) { Screen() } } }
    }
}

@Composable
private fun Screen() {
    val ctx = LocalContext.current
    val mode by Status.mode.collectAsState()
    val detail by Status.detail.collectAsState()
    val logs by Status.lines.collectAsState()
    var url by remember { mutableStateOf(Store.subUrl) }
    var profiles by remember { mutableStateOf(Store.profiles) }
    var sel by remember { mutableStateOf(Store.selected) }
    var busy by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf("") }
    var enforced by remember { mutableStateOf(Lockdown.enforced(ctx)) }
    var auto by remember { mutableStateOf(Store.autoConnect) }
    val scope = rememberCoroutineScope()

    val vpn = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) KsVpnService.start(ctx) else msg = "VPN не разрешён"
    }
    val perm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) perm.launch(Manifest.permission.POST_NOTIFICATIONS)
        while (true) { enforced = Lockdown.enforced(ctx); delay(2000) }
    }

    fun connect() {
        val i = VpnService.prepare(ctx)
        if (i != null) vpn.launch(i) else KsVpnService.start(ctx)
    }

    fun load() {
        if (url.isBlank()) { msg = "вставьте ссылку подписки"; return }
        busy = true
        scope.launch {
            try {
                val list = withContext(Dispatchers.IO) { Sub.fetch(url.trim()) }
                Store.subUrl = url.trim(); Store.profiles = list; profiles = list
                if (list.none { it.tag == sel }) { sel = list[0].tag; Store.selected = sel }
                msg = "загружено серверов: ${list.size}"
                if (mode != Mode.IDLE) KsVpnService.start(ctx, KsVpnService.RECONNECT)
            } catch (e: Exception) { msg = "ошибка: ${e.message}" }
            busy = false
        }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("KS VPN", style = MaterialTheme.typography.headlineSmall)

        Card { Column(Modifier.padding(16.dp)) {
            Text(when (mode) {
                Mode.CONNECTED -> "🟢 ПОДКЛЮЧЕНО"
                Mode.BLOCKED -> "🔴 ИНТЕРНЕТ ЗАБЛОКИРОВАН"
                Mode.CONNECTING -> "🟡 ПОДКЛЮЧЕНИЕ…"
                Mode.IDLE -> "⚪ СЕРВИС НЕ ЗАПУЩЕН"
            }, style = MaterialTheme.typography.titleMedium)
            Text(detail)
            Text("Сервер: " + (profiles.firstOrNull { it.tag == sel }?.name ?: "—"))
        } }

        if (!enforced) Card(colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("⚠ Включите системную блокировку", style = MaterialTheme.typography.titleMedium)
                Text("Настройки → Сеть и интернет → VPN → KS VPN → «Постоянная VPN» + " +
                     "«Блокировать подключения без VPN». Без этого при убийстве процесса " +
                     "Android пустит трафик мимо VPN — ни одно приложение это не обойдёт.")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) { Text("Настройки VPN") }
                    OutlinedButton(onClick = {
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("adb", Lockdown.ADB))
                        msg = "adb-команды скопированы"
                    }) { Text("adb") }
                }
            }
        }

        OutlinedTextField(url, { url = it }, label = { Text("Ссылка подписки") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { load() }, enabled = !busy) { Text(if (busy) "Загрузка…" else "Загрузить") }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { connect() }) { Text(if (mode == Mode.CONNECTED) "Переподключить" else "Подключить") }
            OutlinedButton(onClick = { KsVpnService.start(ctx, KsVpnService.BLOCK) }) { Text("Блокировать") }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(auto, { auto = it; Store.autoConnect = it })
            Spacer(Modifier.width(8.dp)); Text("Автозапуск при загрузке телефона")
        }

        if (msg.isNotBlank()) Text(msg)
        Text("Серверы (${profiles.size})", style = MaterialTheme.typography.titleMedium)
        profiles.take(300).forEach { p ->
            Row(Modifier.fillMaxWidth().clickable {
                sel = p.tag; Store.selected = p.tag
                if (mode != Mode.IDLE) KsVpnService.start(ctx, KsVpnService.RECONNECT)
            }.padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = p.tag == sel, onClick = null)
                Text(p.name, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
        Text("Лог", style = MaterialTheme.typography.titleMedium)
        logs.takeLast(25).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

// ========== BootReceiver ==========
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        Store.init(c)
        if (!Store.autoConnect) return
        runCatching { KsVpnService.start(c, KsVpnService.START) }
            .onFailure { Log.e("ksvpn", "boot start", it) }
    }
}
