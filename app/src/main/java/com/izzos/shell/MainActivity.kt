package com.izzos.shell

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {
    private lateinit var startMenu: View
    private lateinit var appList: LinearLayout
    private lateinit var search: EditText
    private val handler = Handler(Looper.getMainLooper())
    private var apps: List<AppEntry> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        startMenu = findViewById(R.id.startMenu)
        appList = findViewById(R.id.appList)
        search = findViewById(R.id.searchApps)

        findViewById<Button>(R.id.startButton).setOnClickListener {
            startMenu.visibility = if (startMenu.visibility == View.VISIBLE) View.GONE else View.VISIBLE
        }

        apps = loadLaunchableApps()
        renderApps(apps)

        search.setOnEditorActionListener { _, _, _ ->
            filterApps(search.text.toString())
            true
        }
        search.setOnKeyListener { _, _, _ ->
            filterApps(search.text.toString())
            false
        }

        updateClock()
    }

    private fun loadLaunchableApps(): List<AppEntry> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager.queryIntentActivities(intent, PackageManager.MATCH_ALL)
            .map {
                AppEntry(
                    label = it.loadLabel(packageManager).toString(),
                    packageName = it.activityInfo.packageName
                )
            }
            .distinctBy { it.packageName }
            .sortedBy { it.label.lowercase(Locale.getDefault()) }
    }

    private fun filterApps(query: String) {
        if (query.isBlank()) renderApps(apps)
        else renderApps(apps.filter { it.label.contains(query, ignoreCase = true) })
    }

    private fun renderApps(items: List<AppEntry>) {
        appList.removeAllViews()
        items.forEach { app ->
            val row = TextView(this).apply {
                text = app.label
                textSize = 17f
                setTextColor(0xFFFFFFFF.toInt())
                setPadding(12, 18, 12, 18)
                setOnClickListener {
                    packageManager.getLaunchIntentForPackage(app.packageName)?.let(::startActivity)
                    startMenu.visibility = View.GONE
                }
            }
            appList.addView(row)
        }
    }

    private fun updateClock() {
        val clock = findViewById<TextView>(R.id.clock)
        val formatter = SimpleDateFormat("HH:mm  dd MMM", Locale.getDefault())
        val runnable = object : Runnable {
            override fun run() {
                clock.text = formatter.format(Date())
                handler.postDelayed(this, 30_000)
            }
        }
        handler.post(runnable)
    }

    data class AppEntry(val label: String, val packageName: String)
}
