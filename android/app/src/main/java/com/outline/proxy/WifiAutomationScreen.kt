package com.outline.proxy

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

@Composable
fun WifiAutomationScreen(
    store: AutomationStore,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val initial = remember { store.load() }
    var wifiEnabled by remember { mutableStateOf(initial.wifiAutomationEnabled) }
    var wifiMode by remember { mutableStateOf(initial.wifiMode) }
    val ssids = remember { initial.trustedSsids.toMutableStateList() }

    var refresh by remember { mutableIntStateOf(0) }
    var newSsid by remember { mutableStateOf("") }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refresh++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val locationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { refresh++ }

    @Suppress("UNUSED_EXPRESSION")
    refresh
    val hasLocationPermission = LinkProbe.canReadWifiSsid(context)
    val currentSsid = LinkProbe.currentWifiSsid(context)

    fun persist() {
        store.save(
            AutomationConfig(
                pauseOnAirplaneMode = store.load().pauseOnAirplaneMode,
                wifiAutomationEnabled = wifiEnabled,
                wifiMode = wifiMode,
                trustedSsids = ssids.toSet(),
            ),
        )
    }

    SubScreen(
        title = stringResource(R.string.auto_wifi_title),
        icon = Icons.Filled.Wifi,
        onBack = onBack,
    ) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
        ) {
            // Master toggle card
            SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.auto_wifi_enabled),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            stringResource(R.string.auto_wifi_enabled_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                    Switch(
                        checked = wifiEnabled,
                        onCheckedChange = {
                            wifiEnabled = it
                            persist()
                        },
                    )
                }
            }

            if (wifiEnabled) {
                // Mode selector
                SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                    Column {
                        Text(
                            stringResource(R.string.auto_wifi_mode_title),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )

                        WifiModeOption(
                            title = stringResource(R.string.auto_wifi_mode_pause),
                            description = stringResource(R.string.auto_wifi_mode_pause_desc),
                            selected = wifiMode == WifiRuleMode.PAUSE_ON_SELECTED,
                            onClick = {
                                wifiMode = WifiRuleMode.PAUSE_ON_SELECTED
                                persist()
                            },
                        )

                        Spacer(Modifier.height(8.dp))

                        WifiModeOption(
                            title = stringResource(R.string.auto_wifi_mode_connect),
                            description = stringResource(R.string.auto_wifi_mode_connect_desc),
                            selected = wifiMode == WifiRuleMode.CONNECT_ON_SELECTED,
                            onClick = {
                                wifiMode = WifiRuleMode.CONNECT_ON_SELECTED
                                persist()
                            },
                        )
                    }
                }

                // Location permission warning card if missing
                if (!hasLocationPermission) {
                    SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                        Column {
                            Text(
                                stringResource(R.string.auto_wifi_permission_title),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.error,
                            )
                            Text(
                                stringResource(R.string.auto_wifi_permission_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(top = 4.dp, bottom = 12.dp),
                            )
                            OutlinedButton(
                                onClick = { locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION) },
                                shape = RoundedCornerShape(16.dp),
                            ) {
                                Text(stringResource(R.string.auto_wifi_permission_btn))
                            }
                        }
                    }
                }

                // Add network card
                SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                    Column {
                        val currentText = when {
                            currentSsid != null -> stringResource(R.string.auto_wifi_current_network, currentSsid)
                            hasLocationPermission -> stringResource(R.string.auto_wifi_current_none)
                            else -> stringResource(R.string.auto_wifi_current_unknown)
                        }

                        Text(
                            currentText,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.padding(bottom = 12.dp),
                        )

                        if (currentSsid != null && !ssids.contains(currentSsid)) {
                            OutlinedButton(
                                onClick = {
                                    if (store.addSsid(currentSsid)) {
                                        ssids.add(currentSsid)
                                        persist()
                                    }
                                },
                                shape = RoundedCornerShape(16.dp),
                                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                            ) {
                                Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.auto_wifi_add_current))
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            OutlinedTextField(
                                value = newSsid,
                                onValueChange = { newSsid = it },
                                label = { Text(stringResource(R.string.auto_wifi_add_manual_hint)) },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                shape = RoundedCornerShape(16.dp),
                            )
                            Spacer(Modifier.width(8.dp))
                            Button(
                                onClick = {
                                    val clean = AutomationPolicy.normalizeSsid(newSsid)
                                    if (clean != null && !ssids.contains(clean)) {
                                        if (store.addSsid(clean)) {
                                            ssids.add(clean)
                                            persist()
                                            newSsid = ""
                                        }
                                    }
                                },
                                enabled = newSsid.isNotBlank(),
                                shape = RoundedCornerShape(16.dp),
                            ) {
                                Text(stringResource(R.string.auto_wifi_btn_add))
                            }
                        }
                    }
                }

                // Networks list
                SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                    Column {
                        Text(
                            stringResource(R.string.auto_wifi_networks_header),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )

                        if (ssids.isEmpty()) {
                            Text(
                                stringResource(R.string.auto_wifi_empty_list),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(vertical = 8.dp),
                            )
                        } else {
                            ssids.forEach { ssid ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f),
                                    ) {
                                        Icon(
                                            Icons.Filled.Wifi,
                                            contentDescription = null,
                                            tint = BrandBlue,
                                            modifier = Modifier.size(20.dp),
                                        )
                                        Spacer(Modifier.width(12.dp))
                                        Text(
                                            ssid,
                                            style = MaterialTheme.typography.bodyLarge,
                                            fontWeight = FontWeight.Medium,
                                        )
                                    }
                                    IconButton(
                                        onClick = {
                                            store.removeSsid(ssid)
                                            ssids.remove(ssid)
                                            persist()
                                        },
                                    ) {
                                        Icon(
                                            Icons.Filled.Delete,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun WifiModeOption(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(
            selected = selected,
            onClick = onClick,
            modifier = Modifier.padding(top = 2.dp),
        )
        Spacer(Modifier.width(8.dp))
        Column {
            Text(
                title,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                color = if (selected) BrandBlue else MaterialTheme.colorScheme.onSurface,
            )
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
    }
}
