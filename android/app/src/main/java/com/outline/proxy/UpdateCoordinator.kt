package com.outline.proxy

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-scoped coordinator keeping UI footer state, startup check, background
 * worker updates, and APK downloads synchronized across Activity recreations.
 */
object UpdateCoordinator {
    data class UiState(
        val available: UpdateChecker.Result.Available? = null,
        val status: String? = null,
        val checking: Boolean = false,
        val downloading: Boolean = false,
        val downloadedApk: String? = null,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val startupCheckStarted = AtomicBoolean(false)

    fun currentBuildId(): String =
        UpdateSchedule.currentBuildId(BuildConfig.CHANNEL, BuildConfig.VERSION_NAME, BuildConfig.GIT_SHA)

    /** Loads any persisted update discovered earlier for this build, or clears stale cache. */
    fun hydrate(context: Context) {
        val appCtx = context.applicationContext
        val store = UpdateStore(appCtx)
        val buildId = currentBuildId()
        if (store.clearIfBuildChanged(buildId)) {
            UpdateNotification.cancel(appCtx)
            _state.update {
                if (!it.downloading) {
                    it.copy(available = null, status = null, downloadedApk = null)
                } else {
                    it
                }
            }
            return
        }

        val current = _state.value
        if (current.available == null && !current.downloading && current.downloadedApk == null) {
            store.loadAvailable(buildId)?.let { cached ->
                _state.update {
                    it.copy(
                        available = cached,
                        status = appCtx.getString(R.string.upd_available_tap, cached.label),
                    )
                }
            }
        }
    }

    /** Runs one quiet update check shortly after cold process launch. */
    fun scheduleStartupCheck(context: Context) {
        if (!startupCheckStarted.compareAndSet(false, true)) return
        val appCtx = context.applicationContext
        scope.launch {
            delay(UpdateSchedule.STARTUP_DELAY_MS)
            val current = _state.value
            if (current.checking || current.downloading || current.downloadedApk != null || current.available != null) {
                return@launch
            }
            _state.update { it.copy(checking = true) }
            val result = UpdateChecker.check()
            val now = System.currentTimeMillis()
            val store = UpdateStore(appCtx)
            val buildId = currentBuildId()
            when (result) {
                is UpdateChecker.Result.Available -> {
                    store.recordCheck(now)
                    store.saveAvailable(result, buildId)
                    _state.update {
                        it.copy(
                            checking = false,
                            available = result,
                            status = appCtx.getString(R.string.upd_available_tap, result.label),
                        )
                    }
                }
                UpdateChecker.Result.UpToDate -> {
                    store.recordCheck(now)
                    store.clearAvailable()
                    UpdateNotification.cancel(appCtx)
                    _state.update {
                        it.copy(
                            checking = false,
                            available = null,
                        )
                    }
                }
                is UpdateChecker.Result.Failed -> {
                    _state.update { it.copy(checking = false) }
                }
            }
        }
    }

    /**
     * Interactive check triggered from the Home footer or an update notification.
     * Reuses a known available release without re-querying GitHub.
     */
    fun checkManually(
        context: Context,
        onAvailable: (UpdateChecker.Result.Available) -> Unit,
    ) {
        val appCtx = context.applicationContext
        val current = _state.value
        if (current.checking || current.downloading) return
        current.available?.let { known ->
            UpdateNotification.cancel(appCtx)
            onAvailable(known)
            return
        }

        _state.update {
            it.copy(
                checking = true,
                status = appCtx.getString(R.string.upd_checking),
            )
        }
        scope.launch {
            val result = UpdateChecker.check()
            val now = System.currentTimeMillis()
            val store = UpdateStore(appCtx)
            val buildId = currentBuildId()
            when (result) {
                is UpdateChecker.Result.Available -> {
                    store.recordCheck(now)
                    store.saveAvailable(result, buildId)
                    UpdateNotification.cancel(appCtx)
                    _state.update {
                        it.copy(
                            checking = false,
                            available = result,
                            status = appCtx.getString(R.string.upd_available_tap, result.label),
                        )
                    }
                    onAvailable(result)
                }
                UpdateChecker.Result.UpToDate -> {
                    store.recordCheck(now)
                    store.clearAvailable()
                    UpdateNotification.cancel(appCtx)
                    _state.update {
                        it.copy(
                            checking = false,
                            available = null,
                            status = appCtx.getString(R.string.upd_up_to_date),
                        )
                    }
                }
                is UpdateChecker.Result.Failed -> {
                    _state.update {
                        it.copy(
                            checking = false,
                            status = appCtx.getString(R.string.upd_check_failed, result.reason),
                        )
                    }
                }
            }
        }
    }

    /** Downloads the APK in the process scope so progress survives Activity recreation. */
    fun startDownload(context: Context, available: UpdateChecker.Result.Available) {
        val appCtx = context.applicationContext
        if (_state.value.downloading) return
        UpdateNotification.cancel(appCtx)
        _state.update {
            it.copy(
                downloading = true,
                status = appCtx.getString(R.string.upd_downloading_pct, 0),
            )
        }
        scope.launch {
            val outcome = UpdateChecker.download(appCtx, available) { percent ->
                _state.update { current ->
                    if (current.downloading) {
                        current.copy(status = appCtx.getString(R.string.upd_downloading_pct, percent))
                    } else {
                        current
                    }
                }
            }
            when (outcome) {
                is UpdateChecker.Download.Saved -> {
                    _state.update {
                        it.copy(
                            downloading = false,
                            downloadedApk = outcome.uri,
                            status = appCtx.getString(R.string.upd_downloaded_tap),
                        )
                    }
                }
                is UpdateChecker.Download.Failed -> {
                    _state.update {
                        it.copy(
                            downloading = false,
                            status = appCtx.getString(R.string.upd_download_failed, outcome.reason),
                        )
                    }
                }
            }
        }
    }

    /** Mirrors results from [UpdateWorker] into live in-memory UI state if the process is running. */
    fun onBackgroundResult(context: Context, result: UpdateChecker.Result) {
        val appCtx = context.applicationContext
        _state.update { current ->
            if (current.downloading || current.downloadedApk != null) {
                return@update current
            }
            when (result) {
                is UpdateChecker.Result.Available -> current.copy(
                    available = result,
                    status = appCtx.getString(R.string.upd_available_tap, result.label),
                )
                UpdateChecker.Result.UpToDate -> {
                    if (current.available != null) {
                        current.copy(available = null, status = null)
                    } else {
                        current
                    }
                }
                is UpdateChecker.Result.Failed -> current
            }
        }
    }
}
