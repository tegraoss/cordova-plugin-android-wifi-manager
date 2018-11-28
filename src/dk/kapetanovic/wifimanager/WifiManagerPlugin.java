package dk.kapetanovic.wifimanager;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.DhcpInfo;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.ConnectivityManager;
import android.provider.Settings;
import android.text.TextUtils;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

public class WifiManagerPlugin extends CordovaPlugin {
    private static final String ACCESS_COARSE_LOCATION = Manifest.permission.ACCESS_COARSE_LOCATION;
    private static final String ACCESS_FINE_LOCATION = Manifest.permission.ACCESS_FINE_LOCATION;
    private static final String ACTION_MANAGE_WRITE_SETTINGS = Settings.ACTION_MANAGE_WRITE_SETTINGS;

    private static final String WIFI_AP_STATE_CHANGED_ACTION = getStringField("WIFI_AP_STATE_CHANGED_ACTION");
    private static final String EXTRA_WIFI_AP_STATE = getStringField("EXTRA_WIFI_AP_STATE");
    private static final String EXTRA_PREVIOUS_WIFI_AP_STATE = getStringField("EXTRA_PREVIOUS_WIFI_AP_STATE");

    private static final int WIFI_AP_STATE_DISABLED = getIntField("WIFI_AP_STATE_DISABLED");
    private static final int WIFI_AP_STATE_DISABLING = getIntField("WIFI_AP_STATE_DISABLING");
    private static final int WIFI_AP_STATE_ENABLED = getIntField("WIFI_AP_STATE_ENABLED");
    private static final int WIFI_AP_STATE_ENABLING = getIntField("WIFI_AP_STATE_ENABLING");
    private static final int WIFI_AP_STATE_FAILED = getIntField("WIFI_AP_STATE_FAILED");

    private static final int REQUEST_CODE_SCAN_RESULTS = 0;
    private static final int REQUEST_CODE_WIFI_AP_ENABLE = 1;

    private static final String ACTION_ADD_NETWORK = "addNetwork";
    private static final String ACTION_DISABLE_NETWORK = "disableNetwork";
    private static final String ACTION_DISCONNECT = "disconnect";
    private static final String ACTION_ENABLE_NETWORK = "enableNetwork";
    private static final String ACTION_GET_CONFIGURATION_NETWORKS = "getConfiguredNetworks";
    private static final String ACTION_GET_CONNECTION_INFO = "getConnectionInfo";
    private static final String ACTION_GET_DHCP_INFO = "getDhcpInfo";
    private static final String ACTION_GET_SCAN_RESULTS = "getScanResults";
    private static final String ACTION_GET_WIFI_AP_CONFIGURATION = "getWifiApConfiguration";
    private static final String ACTION_GET_WIFI_AP_STATE = "getWifiApState";
    private static final String ACTION_GET_WIFI_STATE = "getWifiState";
    private static final String ACTION_IS_SCAN_ALWAYS_AVAILABLE = "isScanAlwaysAvailable";
    private static final String ACTION_IS_WIFI_AP_ENABLED = "isWifiApEnabled";
    private static final String ACTION_IS_WIFI_ENABLED = "isWifiEnabled";
    private static final String ACTION_REASSOCIATE = "reassociate";
    private static final String ACTION_RECONNECT = "reconnect";
    private static final String ACTION_REMOVE_NETWORK = "removeNetwork";
    private static final String ACTION_SAVE_CONFIGURATION = "saveConfiguration";
    private static final String ACTION_SET_WIFI_AP_CONFIGURATION = "setWifiApConfiguration";
    private static final String ACTION_SET_WIFI_AP_ENABLED = "setWifiApEnabled";
    private static final String ACTION_SET_WIFI_ENABLED = "setWifiEnabled";
    private static final String ACTION_START_SCAN = "startScan";
    private static final String ACTION_UPDATE_NETWORK = "updateNetwork";
    private static final String ACTION_ON_CHANGE = "onChange";
    private static final String SAVE_EAP_CONFIG = "saveEapConfig";

    private WifiManager wifiManager;
    private volatile CallbackContext onChange;
    private BroadcastReceiver broadcastReceiver = new WifiBroadcastReceiver();
    private final List<CallbackContext> scanResultsCallbacks = new ArrayList<CallbackContext>();
    private final List<CallbackClosure> wifiApEnableCallbacks = new ArrayList<CallbackClosure>();

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);

        wifiManager = (WifiManager) cordova.getActivity()
                .getApplication()
                .getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
    }

    @Override
    public void onResume(boolean multitasking) {
        super.onResume(multitasking);

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiManager.NETWORK_IDS_CHANGED_ACTION);
        intentFilter.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);
        intentFilter.addAction(WifiManager.RSSI_CHANGED_ACTION);
        intentFilter.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        intentFilter.addAction(WifiManager.SUPPLICANT_CONNECTION_CHANGE_ACTION);
        intentFilter.addAction(WifiManager.SUPPLICANT_STATE_CHANGED_ACTION);
        intentFilter.addAction(WifiManager.WIFI_STATE_CHANGED_ACTION);
        if(WIFI_AP_STATE_CHANGED_ACTION != null) intentFilter.addAction(WIFI_AP_STATE_CHANGED_ACTION);

        cordova.getActivity().registerReceiver(broadcastReceiver, intentFilter);
    }

    @Override
    public void onPause(boolean multitasking) {
        super.onPause(multitasking);

        cordova.getActivity().unregisterReceiver(broadcastReceiver);
    }

    @Override
    public void onRequestPermissionResult(int requestCode, String[] permissions, int[] grantResults) throws JSONException {
        if(requestCode == REQUEST_CODE_SCAN_RESULTS) {
            boolean hasPermission = true;

            for(int result : grantResults) {
                hasPermission = hasPermission && result == PackageManager.PERMISSION_GRANTED;
            }

            synchronized(scanResultsCallbacks) {
                if(hasPermission) {
                    List<ScanResult> scanResults = wifiManager.getScanResults();
                    JSONArray json = toJSON(scanResults);
                    for(CallbackContext callbackContext : scanResultsCallbacks) {
                        callbackContext.sendPluginResult(OK(json));
                    }
                } else {
                    String message = "Permission denied " + TextUtils.join(", ", permissions);
                    for(CallbackContext callbackContext : scanResultsCallbacks) {
                        callbackContext.sendPluginResult(ERROR(message));
                    }
                }

                scanResultsCallbacks.clear();
            }
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if(requestCode == REQUEST_CODE_WIFI_AP_ENABLE) {
            boolean hasPermission = hasWriteSettingsPermission();

            synchronized(wifiApEnableCallbacks) {
                for(CallbackClosure callbackClosure : wifiApEnableCallbacks) {
                    CallbackContext callbackContext = callbackClosure.getCallbackContext();

                    try {
                        if(hasPermission) {
                            setWifiApEnabledWithPermission(callbackClosure.getArgs(), callbackContext);
                        } else {
                            callbackContext.sendPluginResult(ERROR("Permission denied WRITE_SETTINGS"));
                        }
                    } catch(JSONException e) {
                        PluginResult result = new PluginResult(PluginResult.Status.JSON_EXCEPTION, e.getMessage());
                        callbackContext.sendPluginResult(result);
                    }
                }

                wifiApEnableCallbacks.clear();
            }
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if(action.equals(ACTION_ADD_NETWORK)) addNetwork(args, callbackContext);
        else if(action.equals(ACTION_DISABLE_NETWORK)) disableNetwork(args, callbackContext);
        else if(action.equals(ACTION_DISCONNECT)) disconnect(callbackContext);
        else if(action.equals(ACTION_ENABLE_NETWORK)) enableNetwork(args, callbackContext);
        else if(action.equals(ACTION_GET_CONFIGURATION_NETWORKS)) getConfiguredNetworks(callbackContext);
        else if(action.equals(ACTION_GET_CONNECTION_INFO)) getConnectionInfo(callbackContext);
        else if(action.equals(ACTION_GET_DHCP_INFO)) getDhcpInfo(callbackContext);
        else if(action.equals(ACTION_GET_SCAN_RESULTS)) getScanResults(callbackContext);
        else if(action.equals(ACTION_GET_WIFI_AP_CONFIGURATION)) return getWifiApConfiguration(callbackContext);
        else if(action.equals(ACTION_GET_WIFI_AP_STATE)) return getWifiApState(callbackContext);
        else if(action.equals(ACTION_GET_WIFI_STATE)) getWifiState(callbackContext);
        else if(action.equals(ACTION_IS_SCAN_ALWAYS_AVAILABLE)) isScanAlwaysAvailable(callbackContext);
        else if(action.equals(ACTION_IS_WIFI_AP_ENABLED)) return isWifiApEnabled(callbackContext);
        else if(action.equals(ACTION_IS_WIFI_ENABLED)) isWifiEnabled(callbackContext);
        else if(action.equals(ACTION_REASSOCIATE)) reassociate(callbackContext);
        else if(action.equals(SAVE_EAP_CONFIG)) saveEapConfig(callbackContext, data);
        else if(action.equals(ACTION_RECONNECT)) reconnect(callbackContext);
        else if(action.equals(ACTION_REMOVE_NETWORK)) removeNetwork(args, callbackContext);
        else if(action.equals(ACTION_SAVE_CONFIGURATION)) saveConfiguration(callbackContext);
        else if(action.equals(ACTION_SET_WIFI_AP_CONFIGURATION)) return setWifiApConfiguration(args, callbackContext);
        else if(action.equals(ACTION_SET_WIFI_AP_ENABLED)) return setWifiApEnabled(args, callbackContext);
        else if(action.equals(ACTION_SET_WIFI_ENABLED)) setWifiEnabled(args, callbackContext);
        else if(action.equals(ACTION_START_SCAN)) startScan(callbackContext);
        else if(action.equals(ACTION_UPDATE_NETWORK)) updateNetwork(args, callbackContext);
        else if(action.equals(ACTION_ON_CHANGE)) onChange(callbackContext);
        else return false;

        return true;
    }

    private void addNetwork(JSONArray args, CallbackContext callbackContext) throws JSONException {
        JSONObject json = args.getJSONObject(0);
        WifiConfiguration wifiConfig = fromJSONWifiConfiguration(json);
        int networkId = wifiManager.addNetwork(wifiConfig);
        callbackContext.sendPluginResult(OK(networkId));
    }

    private void disableNetwork(JSONArray args, CallbackContext callbackContext) throws JSONException {
        int networkId = args.getInt(0);
        boolean result = wifiManager.disableNetwork(networkId);
        callbackContext.sendPluginResult(OK(result));
    }

    private void disconnect(CallbackContext callbackContext) throws JSONException {
        boolean result = wifiManager.disconnect();
        callbackContext.sendPluginResult(OK(result));
    }

    private void enableNetwork(JSONArray args, CallbackContext callbackContext) throws JSONException {
        int networkId = args.getInt(0);
        boolean attemptConnect = args.getBoolean(1);
        boolean result = wifiManager.enableNetwork(networkId, attemptConnect);
        callbackContext.sendPluginResult(OK(result));
    }

    private void getConfiguredNetworks(CallbackContext callbackContext) throws JSONException {
        List<WifiConfiguration> networks = wifiManager.getConfiguredNetworks();
        JSONArray json = new JSONArray();

        if(networks != null) {
            for(WifiConfiguration wifiConfig : networks) {
                json.put(toJSON(wifiConfig));
            }
        }

        callbackContext.sendPluginResult(OK(json));
    }

    private void getConnectionInfo(CallbackContext callbackContext) throws JSONException {
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        JSONObject json = toJSON(wifiInfo);
        callbackContext.sendPluginResult(OK(json));
    }

    private void getDhcpInfo(CallbackContext callbackContext) throws JSONException {
        DhcpInfo dhcpInfo = wifiManager.getDhcpInfo();
        JSONObject json = toJSON(dhcpInfo);
        callbackContext.sendPluginResult(OK(json));
    }

    private void getScanResults(CallbackContext callbackContext) throws JSONException {
        if(hasLocationPermission()) {
            // We should end up here most of the time
            getScanResultsWithPermission(callbackContext);
        } else {
            synchronized(scanResultsCallbacks) {
                if(hasLocationPermission()) {
                    // We got permission while acquiring lock
                    getScanResultsWithPermission(callbackContext);
                    return;
                }

                scanResultsCallbacks.add(callbackContext);

                if(scanResultsCallbacks.size() == 1) {
                    cordova.requestPermission(this, REQUEST_CODE_SCAN_RESULTS, ACCESS_COARSE_LOCATION);
                }
            }
        }
    }

    private void getScanResultsWithPermission(CallbackContext callbackContext) throws JSONException {
        List<ScanResult> scanResults = wifiManager.getScanResults();
        JSONArray json = toJSON(scanResults);
        callbackContext.sendPluginResult(OK(json));
    }

    private boolean getWifiApConfiguration(CallbackContext callbackContext) throws JSONException {
        Class<?> klass = wifiManager.getClass();

        try {
            Method method = klass.getDeclaredMethod("getWifiApConfiguration");
            WifiConfiguration wifiConfiguration = (WifiConfiguration) method.invoke(wifiManager);
            JSONObject json = toJSON(wifiConfiguration);
            callbackContext.sendPluginResult(OK(json));
        } catch(NoSuchMethodException e) {
            return false;
        } catch(InvocationTargetException e) {
            callbackContext.sendPluginResult(ERROR(e.getCause().getMessage()));
        } catch(IllegalAccessException e) {
            callbackContext.sendPluginResult(ERROR(e.getMessage()));
        }

        return true;
    }

    private boolean getWifiApState(CallbackContext callbackContext) throws JSONException {
        Class<?> klass = wifiManager.getClass();

        try {
            Method method = klass.getDeclaredMethod("getWifiApState");
            int result = (Integer) method.invoke(wifiManager);
            String wifiApState = toStringWifiApState(result);
            callbackContext.sendPluginResult(OK(wifiApState));
        } catch(NoSuchMethodException e) {
            return false;
        } catch(InvocationTargetException e) {
            callbackContext.sendPluginResult(ERROR(e.getCause().getMessage()));
        } catch(IllegalAccessException e) {
            callbackContext.sendPluginResult(ERROR(e.getMessage()));
        }

        return true;
    }

    private void getWifiState(CallbackContext callbackContext) throws JSONException {
        String wifiState = toStringWifiState(wifiManager.getWifiState());
        callbackContext.sendPluginResult(OK(wifiState));
    }

    private void isScanAlwaysAvailable(CallbackContext callbackContext) throws JSONException {
        boolean available = wifiManager.isScanAlwaysAvailable();
        callbackContext.sendPluginResult(OK(available));
    }

    private boolean isWifiApEnabled(CallbackContext callbackContext) throws JSONException {
        Class<?> klass = wifiManager.getClass();

        try {
            Method method = klass.getDeclaredMethod("isWifiApEnabled");
            boolean enabled = (Boolean) method.invoke(wifiManager);
            callbackContext.sendPluginResult(OK(enabled));
        } catch(NoSuchMethodException e) {
            return false;
        } catch(InvocationTargetException e) {
            callbackContext.sendPluginResult(ERROR(e.getCause().getMessage()));
        } catch(IllegalAccessException e) {
            callbackContext.sendPluginResult(ERROR(e.getMessage()));
        }

        return true;
    }

    // EAP CONFIG

    private boolean saveEapConfig(CallbackContext callbackContext, JSONArray data) {
        try {
            WifiConfiguration con = new WifiConfiguration();
            con = this.setWifiConfigurations(con, data.getString(0), data.getString(1), data.getString(2));

            boolean res1 = wifiManager.setWifiEnabled(true);
            int networkId = wifiManager.addNetwork(con);
            boolean b = wifiManager.enableNetwork(networkId, true);
            boolean isWifiConnected = wifiManager.isWifiEnabled();
            Log.d("Wifi Connection", "Wifi Connected: " + isWifiConnected);
            System.out.println("Wifi Connected: " + isWifiConnected);
            System.out.println("Wifi Info: " + wifiManager.getConnectionInfo());
            System.out.println("Wifi enterpriseConfig info: " + con.enterpriseConfig);

            if(!res1 || networkId == -1 || !b || !isWifiConnected) {
                callbackContext.error("Sem Conexão!");
                return false;
            }
            else {
                callbackContext.success("Conectado com sucesso!");
                return true;
            }
        } catch (Exception e) {
            callbackContext.error(e.getMessage());
            return false;
        }
    }

    // END EAP CONFIG
      

    private void isWifiEnabled(CallbackContext callbackContext) throws JSONException {
        boolean enabled = wifiManager.isWifiEnabled();
        callbackContext.sendPluginResult(OK(enabled));
    }

    private void reassociate(CallbackContext callbackContext) throws JSONException {
        boolean result = wifiManager.reassociate();
        callbackContext.sendPluginResult(OK(result));
    }

    private void reconnect(CallbackContext callbackContext) throws JSONException {
        boolean result = wifiManager.reconnect();
        callbackContext.sendPluginResult(OK(result));
    }

    private void removeNetwork(JSONArray args, CallbackContext callbackContext) throws JSONException {
        int networkId = args.getInt(0);
        boolean result = wifiManager.removeNetwork(networkId);
        callbackContext.sendPluginResult(OK(result));
    }

    private void saveConfiguration(CallbackContext callbackContext) throws JSONException {
        boolean result = wifiManager.saveConfiguration();
        callbackContext.sendPluginResult(OK(result));
    }

    private boolean setWifiApConfiguration(JSONArray args, CallbackContext callbackContext) throws JSONException {
        Class<?> klass = wifiManager.getClass();
        JSONObject json = args.getJSONObject(0);
        WifiConfiguration wifiConfig = fromJSONWifiConfiguration(json);

        try {
            Method method = klass.getDeclaredMethod("setWifiApConfiguration", WifiConfiguration.class);
            boolean result = (Boolean) method.invoke(wifiManager, wifiConfig);
            callbackContext.sendPluginResult(OK(result));
        } catch(NoSuchMethodException e) {
            return false;
        } catch(InvocationTargetException e) {
            callbackContext.sendPluginResult(ERROR(e.getCause().getMessage()));
        } catch(IllegalAccessException e) {
            callbackContext.sendPluginResult(ERROR(e.getMessage()));
        }

        return true;
    }

    private boolean setWifiApEnabled(JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (hasWriteSettingsPermission()) {
            return setWifiApEnabledWithPermission(args, callbackContext);
        } else {
            synchronized(wifiApEnableCallbacks) {
                if(hasWriteSettingsPermission()) {
                    return setWifiApEnabledWithPermission(args, callbackContext);
                }

                try {
                    Class<?> klass = wifiManager.getClass();
                    klass.getDeclaredMethod("setWifiApEnabled", WifiConfiguration.class, boolean.class);
                } catch(NoSuchMethodException e) {
                    return false;
                }

                wifiApEnableCallbacks.add(new CallbackClosure(args, callbackContext));

                if(wifiApEnableCallbacks.size() == 1) {
                    Intent intent = new Intent(ACTION_MANAGE_WRITE_SETTINGS);
                    cordova.startActivityForResult(this, intent, REQUEST_CODE_WIFI_AP_ENABLE);
                }

                return true;
            }
        }
    }

    private boolean setWifiApEnabledWithPermission(JSONArray args, CallbackContext callbackContext) throws JSONException {
        Class<?> klass = wifiManager.getClass();
        JSONObject json = args.getJSONObject(0);
        WifiConfiguration wifiConfig = fromJSONWifiConfiguration(json);
        boolean enabled = args.getBoolean(1);

        try {
            Method method = klass.getDeclaredMethod("setWifiApEnabled", WifiConfiguration.class, boolean.class);
            boolean result = (Boolean) method.invoke(wifiManager, wifiConfig, enabled);
            callbackContext.sendPluginResult(OK(result));
        } catch(NoSuchMethodException e) {
            return false;
        } catch(InvocationTargetException e) {
            callbackContext.sendPluginResult(ERROR(e.getCause().getMessage()));
        } catch(IllegalAccessException e) {
            callbackContext.sendPluginResult(ERROR(e.getMessage()));
        }

        return true;
    }

    private void setWifiEnabled(JSONArray args, CallbackContext callbackContext) throws JSONException {
        boolean enabled = args.getBoolean(0);
        boolean result = wifiManager.setWifiEnabled(enabled);
        callbackContext.sendPluginResult(OK(result));
    }

    private void startScan(CallbackContext callbackContext) throws JSONException {
        boolean result = wifiManager.startScan();
        callbackContext.sendPluginResult(OK(result));
    }

    private void updateNetwork(JSONArray args, CallbackContext callbackContext) throws JSONException {
        JSONObject json = args.getJSONObject(0);
        WifiConfiguration wifiConfig = fromJSONWifiConfiguration(json);
        int networkId = wifiManager.updateNetwork(wifiConfig);
        callbackContext.sendPluginResult(OK(networkId));
    }

    private void onChange(CallbackContext callbackContext) {
        onChange = callbackContext;
    }

    private static JSONObject toJSON(WifiConfiguration wifiConfig) throws JSONException {
        if(wifiConfig == null) return null;

        JSONObject json = new JSONObject();
        json.put("BSSID", wifiConfig.BSSID);
        json.put("SSID", wifiConfig.SSID);

        JSONObject authAlgorithms = new JSONObject();
        authAlgorithms.put("LEAP",
                wifiConfig.allowedAuthAlgorithms.get(WifiConfiguration.AuthAlgorithm.LEAP));
        authAlgorithms.put("OPEN",
                wifiConfig.allowedAuthAlgorithms.get(WifiConfiguration.AuthAlgorithm.OPEN));
        authAlgorithms.put("SHARED",
                wifiConfig.allowedAuthAlgorithms.get(WifiConfiguration.AuthAlgorithm.SHARED));
        json.put("allowedAuthAlgorithms", authAlgorithms);

        JSONObject groupCipher = new JSONObject();
        groupCipher.put("CCMP",
                wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.CCMP));
        groupCipher.put("TKIP",
                wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.TKIP));
        groupCipher.put("WEP104",
                wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.WEP104));
        groupCipher.put("WEP40",
                wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.WEP40));
        json.put("allowedGroupCiphers", groupCipher);

        JSONObject keyManagement = new JSONObject();
        keyManagement.put("IEEE8021X",
                wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.IEEE8021X));
        keyManagement.put("NONE",
                wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.NONE));
        keyManagement.put("WPA_EAP",
                wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_EAP));
        keyManagement.put("WPA_PSK",
                wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_PSK));
        json.put("allowedKeyManagement", keyManagement);

        JSONObject pairwiseCiphers = new JSONObject();
        pairwiseCiphers.put("CCMP",
                wifiConfig.allowedPairwiseCiphers.get(WifiConfiguration.PairwiseCipher.CCMP));
        pairwiseCiphers.put("NONE",
                wifiConfig.allowedPairwiseCiphers.get(WifiConfiguration.PairwiseCipher.NONE));
        pairwiseCiphers.put("TKIP",
                wifiConfig.allowedPairwiseCiphers.get(WifiConfiguration.PairwiseCipher.TKIP));
        json.put("allowedPairwiseCiphers", pairwiseCiphers);

        JSONObject protocols = new JSONObject();
        protocols.put("RSN", wifiConfig.allowedProtocols.get(WifiConfiguration.Protocol.RSN));
        protocols.put("WPA", wifiConfig.allowedProtocols.get(WifiConfiguration.Protocol.WPA));
        json.put("allowedProtocols", protocols);

        json.put("hiddenSSID", wifiConfig.hiddenSSID);
        json.put("networkId", wifiConfig.networkId);
        json.put("preSharedKey", wifiConfig.preSharedKey == null ?
                JSONObject.NULL : wifiConfig.preSharedKey);
        json.put("status", toStringWifiConfigurationStatus(wifiConfig.status));

        JSONArray wepKeys = new JSONArray();
        for(String key : wifiConfig.wepKeys) {
            wepKeys.put(key == null ? JSONObject.NULL : key);
        }

        json.put("wepKeys", wepKeys);
        json.put("wepTxKeyIndex", wifiConfig.wepTxKeyIndex);

        return json;
    }

    private static JSONObject toJSON(WifiInfo wifiInfo) throws JSONException {
        if(wifiInfo == null) return null;

        JSONObject json = new JSONObject();
        json.put("BSSID", wifiInfo.getBSSID());
        json.put("frequency", wifiInfo.getFrequency());
        json.put("hiddenSSID", wifiInfo.getHiddenSSID());
        json.put("ipAddress", wifiInfo.getIpAddress());
        json.put("linkSpeed", wifiInfo.getLinkSpeed());
        json.put("macAddress", wifiInfo.getMacAddress());
        json.put("networkId", wifiInfo.getNetworkId());
        json.put("rssi", wifiInfo.getRssi());
        json.put("SSID", wifiInfo.getSSID());
        json.put("supplicantState", wifiInfo.getSupplicantState());

        return json;
    }

    private static JSONObject toJSON(DhcpInfo dhcpInfo) throws JSONException {
        if(dhcpInfo == null) return null;

        JSONObject json = new JSONObject();
        json.put("dns1", dhcpInfo.dns1);
        json.put("dns2", dhcpInfo.dns2);
        json.put("gateway", dhcpInfo.gateway);
        json.put("ipAddress", dhcpInfo.ipAddress);
        json.put("leaseDuration", dhcpInfo.leaseDuration);
        json.put("netmask", dhcpInfo.netmask);
        json.put("serverAddress", dhcpInfo.serverAddress);

        return json;
    }

    private static JSONObject toJSON(ScanResult scanResult) throws JSONException {
        if(scanResult == null) return null;

        JSONObject json = new JSONObject();
        json.put("BSSID", scanResult.BSSID);
        json.put("SSID", scanResult.SSID);
        json.put("capabilities", scanResult.capabilities);
        json.put("centerFreq0", scanResult.centerFreq0);
        json.put("centerFreq1", scanResult.centerFreq1);
        json.put("channelWidth", toStringChannelWidth(scanResult.channelWidth));
        json.put("frequency", scanResult.frequency);
        json.put("level", scanResult.level);
        json.put("timestamp", scanResult.timestamp);

        return json;
    }

    private static JSONObject toJSON(NetworkInfo networkInfo) throws JSONException {
        if(networkInfo == null) return null;

        JSONObject json = new JSONObject();
        json.put("detailedState", networkInfo.getDetailedState());
        json.put("extraInfo", networkInfo.getExtraInfo());
        json.put("reason", networkInfo.getReason());
        json.put("state", networkInfo.getState());
        json.put("subtype", networkInfo.getSubtype());
        json.put("subtypeName", networkInfo.getSubtypeName());
        json.put("type", toStringNetworkType(networkInfo.getType()));
        json.put("typeName", networkInfo.getTypeName());
        json.put("available", networkInfo.isAvailable());
        json.put("connected", networkInfo.isConnected());
        json.put("connectedOrConnecting", networkInfo.isConnectedOrConnecting());
        json.put("failover", networkInfo.isFailover());
        json.put("roaming", networkInfo.isRoaming());

        return json;
    }

    private static JSONArray toJSON(List<ScanResult> scanResults) throws JSONException {
        JSONArray json = new JSONArray();

        if(scanResults != null) {
            for(ScanResult scanResult : scanResults) {
                json.put(toJSON(scanResult));
            }
        }

        return  json;
    }

    private static WifiConfiguration fromJSONWifiConfiguration(JSONObject json) throws JSONException {
        WifiConfiguration wifiConfig = new WifiConfiguration();

        if(!json.isNull("BSSID")) wifiConfig.BSSID = json.getString("BSSID");
        if(!json.isNull("SSID")) wifiConfig.SSID = json.getString("SSID");

        if(!json.isNull("allowedAuthAlgorithms")) {
            JSONObject authAlgorithms = json.getJSONObject("allowedAuthAlgorithms");

            if(!authAlgorithms.isNull("LEAP")) {
                wifiConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.LEAP);
            }
            if(!authAlgorithms.isNull("OPEN")) {
                wifiConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
            }
            if(!authAlgorithms.isNull("SHARED")) {
                wifiConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
            }
        }

        if(!json.isNull("allowedGroupCiphers")) {
            JSONObject groupCipher = json.getJSONObject("allowedGroupCiphers");

            if(!groupCipher.isNull("CCMP")) {
                wifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
            }
            if(!groupCipher.isNull("TKIP")) {
                wifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
            }
            if(!groupCipher.isNull("WEP104")) {
                wifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
            }
            if(!groupCipher.isNull("WEP40")) {
                wifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
            }
        }

        if(!json.isNull("allowedKeyManagement")) {
            JSONObject keyManagement = json.getJSONObject("allowedKeyManagement");

            if(!keyManagement.isNull("IEEE8021X")) {
                wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
            }
            if(!keyManagement.isNull("NONE")) {
                wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
            }
            if(!keyManagement.isNull("WPA_EAP")) {
                wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);
            }
            if(!keyManagement.isNull("WPA_PSK")) {
                wifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
            }
        }

        if(!json.isNull("allowedPairwiseCiphers")) {
            JSONObject pairwiseCiphers = json.getJSONObject("allowedPairwiseCiphers");

            if(!pairwiseCiphers.isNull("CCMP")) {
                wifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
            }
            if(!pairwiseCiphers.isNull("NONE")) {
                wifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.NONE);
            }
            if(!pairwiseCiphers.isNull("TKIP")) {
                wifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
            }
        }

        if(!json.isNull("allowedProtocols")) {
            JSONObject protocols = json.getJSONObject("allowedProtocols");

            if(!protocols.isNull("RSN")) {
                wifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
            }
            if(!protocols.isNull("WPA")) {
                wifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
            }
        }

        if(!json.isNull("hiddenSSID")) wifiConfig.hiddenSSID = json.getBoolean("hiddenSSID");
        if(!json.isNull("networkId")) wifiConfig.networkId = json.getInt("networkId");
        if(!json.isNull("preSharedKey")) wifiConfig.preSharedKey = json.getString("preSharedKey");
        if(!json.isNull("status")) wifiConfig.status =
                fromStringWifiConfigurationStatus(json.getString("status"));

        if(!json.isNull("wepKeys")) {
            JSONArray wepKeys = json.getJSONArray("wepKeys");

            for(int i = 0; i < wifiConfig.wepKeys.length; i++) {
                if(!wepKeys.isNull(i)) wifiConfig.wepKeys[i] = wepKeys.getString(i);
            }
        }

        if(!json.isNull("wepTxKeyIndex")) wifiConfig.wepTxKeyIndex = json.getInt("wepTxKeyIndex");

        return  wifiConfig;
    }

    private static String toStringWifiApState(int wifiApState) {
        if (wifiApState == WIFI_AP_STATE_DISABLED) return "DISABLED";
        else if (wifiApState == WIFI_AP_STATE_DISABLING) return "DISABLING";
        else if (wifiApState == WIFI_AP_STATE_ENABLED) return "ENABLED";
        else if (wifiApState == WIFI_AP_STATE_ENABLING) return "ENABLING";
        else if (wifiApState == WIFI_AP_STATE_FAILED) return "FAILED";
        else return null;
    }

    private static String toStringWifiState(int wifiState) {
        switch(wifiState) {
            case WifiManager.WIFI_STATE_DISABLED: return "DISABLED";
            case WifiManager.WIFI_STATE_DISABLING: return "DISABLING";
            case WifiManager.WIFI_STATE_ENABLED: return "ENABLED";
            case WifiManager.WIFI_STATE_ENABLING: return "ENABLING";
            case WifiManager.WIFI_STATE_UNKNOWN: return "UNKNOWN";
            default: return null;
        }
    }

    private static String toStringWifiConfigurationStatus(int status) {
        switch(status) {
            case WifiConfiguration.Status.CURRENT: return "CURRENT";
            case WifiConfiguration.Status.DISABLED: return "DISABLED";
            case WifiConfiguration.Status.ENABLED: return "ENABLED";
            default: return null;
        }
    }

    private static String toStringNetworkType(int type) {
        switch(type) {
            case ConnectivityManager.TYPE_MOBILE: return "MOBILE";
            case ConnectivityManager.TYPE_WIFI: return "WIFI";
            case ConnectivityManager.TYPE_WIMAX: return  "WIMAX";
            case ConnectivityManager.TYPE_ETHERNET: return "ETHERNET";
            case ConnectivityManager.TYPE_BLUETOOTH: return "BLUETOOTH";
            default: return null;
        }
    }

    private static String toStringChannelWidth(int channelWidth) {
        switch(channelWidth) {
            case ScanResult.CHANNEL_WIDTH_20MHZ: return "20MHZ";
            case ScanResult.CHANNEL_WIDTH_40MHZ: return "40MHZ";
            case ScanResult.CHANNEL_WIDTH_80MHZ: return "80MHZ";
            case ScanResult.CHANNEL_WIDTH_160MHZ: return "160MHZ";
            case ScanResult.CHANNEL_WIDTH_80MHZ_PLUS_MHZ: return  "80MHZ_PLUS_MHZ";
            default: return null;
        }
    }

    private static int fromStringWifiConfigurationStatus(String status) {
        if(status.equals("CURRENT")) return WifiConfiguration.Status.CURRENT;
        if(status.equals("DISABLED")) return WifiConfiguration.Status.DISABLED;
        if(status.equals("ENABLED")) return WifiConfiguration.Status.ENABLED;
        return -1;
    }

    private static PluginResult OK(Object obj) throws JSONException {
        return createPluginResult(obj, PluginResult.Status.OK);
    }

    private static PluginResult ERROR(Object obj) throws JSONException {
        return createPluginResult(obj, PluginResult.Status.ERROR);
    }

    private static PluginResult createPluginResult(Object obj, PluginResult.Status status) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("data", obj == null ? JSONObject.NULL : obj);
        return new PluginResult(status, json);
    }

    private static int getIntField(String name) {
        try {
            Field field = WifiManager.class.getDeclaredField(name);
            if(!Modifier.isStatic(field.getModifiers())) return -1;
            if(!field.getType().isAssignableFrom(Integer.TYPE)) return -1;
            return field.getInt(null);
        } catch(NoSuchFieldException e) {
            return -1;
        } catch(IllegalAccessException e) {
            return -1;
        }
    }

    private static String getStringField(String name) {
        try {
            Field field = WifiManager.class.getDeclaredField(name);
            if(!Modifier.isStatic(field.getModifiers())) return null;
            if(!field.getType().isAssignableFrom(String.class)) return null;
            return (String) field.get(null);
        } catch(NoSuchFieldException e) {
            return null;
        } catch(IllegalAccessException e) {
            return null;
        }
    }

    private boolean hasLocationPermission() {
        return cordova.hasPermission(ACCESS_COARSE_LOCATION) ||
                cordova.hasPermission(ACCESS_FINE_LOCATION);
    }

    private boolean hasWriteSettingsPermission() {
        Context context = cordova
                .getActivity()
                .getApplication()
                .getApplicationContext();

        return Settings.System.canWrite(context);
    }

    private class WifiBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if(onChange == null) return;

            PluginResult result = null;
            String event = null;
            String action = intent.getAction();
            JSONObject json = new JSONObject();
            JSONObject data = new JSONObject();

            try {
                if(action.equals(WifiManager.NETWORK_IDS_CHANGED_ACTION)) {
                    event = "NETWORK_IDS_CHANGED";
                } else if(action.equals(WifiManager.NETWORK_STATE_CHANGED_ACTION)) {
                    event = "NETWORK_STATE_CHANGED";

                    NetworkInfo networkInfo = intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO);
                    String bssid = intent.getStringExtra(WifiManager.EXTRA_BSSID);
                    WifiInfo wifiInfo = intent.getParcelableExtra(WifiManager.EXTRA_WIFI_INFO);

                    data.put("networkInfo", toJSON(networkInfo));
                    data.put("BSSID", bssid == null ? JSONObject.NULL : bssid);
                    data.put("wifiInfo", wifiInfo == null ? JSONObject.NULL : toJSON(wifiInfo));
                } else if(action.equals(WifiManager.RSSI_CHANGED_ACTION)) {
                    event = "RSSI_CHANGED";
                    int rssi = intent.getIntExtra(WifiManager.EXTRA_NEW_RSSI, 0);
                    data.put("RSSI", rssi);
                } else if(action.equals(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)) {
                    event = "SCAN_RESULTS_AVAILABLE";
                    boolean updated = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false);
                    data.put("resultsUpdated", updated);
                } else if(action.equals(WifiManager.SUPPLICANT_CONNECTION_CHANGE_ACTION)) {
                    event = "SUPPLICANT_CONNECTION_CHANGE";
                    boolean connected = intent.getBooleanExtra(WifiManager.EXTRA_SUPPLICANT_CONNECTED, false);
                    data.put("supplicantConnected", connected);
                } else if(action.equals(WifiManager.SUPPLICANT_STATE_CHANGED_ACTION)) {
                    event = "SUPPLICANT_STATE_CHANGED";

                    SupplicantState newState = intent.getParcelableExtra(WifiManager.EXTRA_NEW_STATE);
                    data.put("newState", newState);

                    if(intent.hasExtra(WifiManager.EXTRA_SUPPLICANT_ERROR)) {
                        int error = intent.getIntExtra(WifiManager.EXTRA_SUPPLICANT_ERROR, 0);
                        String name = error == WifiManager.ERROR_AUTHENTICATING ?
                                "ERROR_AUTHENTICATING" : "ERROR_UNKNOWN";
                        data.put("supplicantError", name);
                    } else {
                        data.put("supplicantError", JSONObject.NULL);
                    }
                } else if(action.equals(WifiManager.WIFI_STATE_CHANGED_ACTION)) {
                    event = "WIFI_STATE_CHANGED";

                    int newState = intent.getIntExtra(WifiManager.EXTRA_WIFI_STATE, 0);
                    int prevState = intent.getIntExtra(WifiManager.EXTRA_PREVIOUS_WIFI_STATE, 0);

                    data.put("wifiState", toStringWifiState(newState));
                    data.put("previousWifiState", toStringWifiState(prevState));
                } else if(WIFI_AP_STATE_CHANGED_ACTION != null && action.equals(WIFI_AP_STATE_CHANGED_ACTION)) {
                    event = "WIFI_AP_STATE_CHANGED";

                    int newState = intent.getIntExtra(EXTRA_WIFI_AP_STATE, 0);
                    int prevState = intent.getIntExtra(EXTRA_PREVIOUS_WIFI_AP_STATE, 0);

                    data.put("wifiApState", toStringWifiApState(newState));
                    data.put("previousWifiApState", toStringWifiApState(prevState));
                }

                json.put("event", event);
                json.put("data", data);

                result = new PluginResult(PluginResult.Status.OK, json);
            } catch(JSONException e) {
                result = new PluginResult(PluginResult.Status.JSON_EXCEPTION, e.getMessage());
            }

            result.setKeepCallback(true);
            onChange.sendPluginResult(result);
        }
    }

    private class CallbackClosure {
        private JSONArray args;
        private CallbackContext callbackContext;

        public CallbackClosure(JSONArray args, CallbackContext callbackContext) {
            this.args = args;
            this.callbackContext = callbackContext;
        }

        public JSONArray getArgs() {
            return args;
        }

        public CallbackContext getCallbackContext() {
            return callbackContext;
        }
    }


    public WifiConfiguration setWifiConfigurations(WifiConfiguration selectedConfig, String mySSID, String userName, String userPass) {

        /********************************Configuration Strings****************************************************/
        final String ENTERPRISE_EAP = "PEAP";
        final String ENTERPRISE_CLIENT_CERT = "";
        final String ENTERPRISE_PRIV_KEY = "";
        //CertificateName = Name given to the certificate while installing it

        /*Optional Params- My wireless Doesn't use these*/
        final String ENTERPRISE_PHASE2 = "";
        final String ENTERPRISE_ANON_IDENT = "";
        final String ENTERPRISE_CA_CERT = ""; // If required: "keystore://CACERT_CaCertificateName"
        /********************************Configuration Strings****************************************************/

        /*AP Name*/
        selectedConfig.SSID = "\"Tegra-Radius\"";

        /*Priority*/
        selectedConfig.priority = 40;

        /*Enable Hidden SSID*/
        selectedConfig.hiddenSSID = true;

        /*Key Mgmnt*/
        selectedConfig.allowedKeyManagement.clear();
        selectedConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
        selectedConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        /*Group Ciphers*/
        selectedConfig.allowedGroupCiphers.clear();
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

        /*Pairwise ciphers*/
        selectedConfig.allowedPairwiseCiphers.clear();
        selectedConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        selectedConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

        /*Protocols*/
        selectedConfig.allowedProtocols.clear();
        selectedConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        selectedConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

        // Enterprise Settings
        // Reflection magic here too, need access to non-public APIs
        try {
            // Let the magic start
            Class[] wcClasses = WifiConfiguration.class.getClasses();
            // null for overzealous java compiler
            Class wcEnterpriseField = null;

            for (Class wcClass : wcClasses)
                if (wcClass.getName().equals(INT_ENTERPRISEFIELD_NAME)) 
                {
                    wcEnterpriseField = wcClass;
                    break;
                }
            boolean noEnterpriseFieldType = false; 
            if(wcEnterpriseField == null)
                noEnterpriseFieldType = true; // Cupcake/Donut access enterprise settings directly

            Field wcefAnonymousId = null, wcefCaCert = null, wcefClientCert = null, wcefEap = null, wcefIdentity = null, wcefPassword = null, wcefPhase2 = null, wcefPrivateKey = null, wcefEngine = null, wcefEngineId = null;
            Field[] wcefFields = WifiConfiguration.class.getFields();
            // Dispatching Field vars
            for (Field wcefField : wcefFields) 
            {
                if (wcefField.getName().equals(INT_ANONYMOUS_IDENTITY))
                    wcefAnonymousId = wcefField;
                else if (wcefField.getName().equals(INT_CA_CERT))
                    wcefCaCert = wcefField;
                else if (wcefField.getName().equals(INT_CLIENT_CERT))
                    wcefClientCert = wcefField;
                else if (wcefField.getName().equals(INT_EAP))
                    wcefEap = wcefField;
                else if (wcefField.getName().equals(INT_IDENTITY))
                    wcefIdentity = wcefField;
                else if (wcefField.getName().equals(INT_PASSWORD))
                    wcefPassword = wcefField;
                else if (wcefField.getName().equals(INT_PHASE2))
                    wcefPhase2 = wcefField;
                else if (wcefField.getName().equals(INT_PRIVATE_KEY))
                    wcefPrivateKey = wcefField;
                else if (wcefField.getName().equals("engine"))
                    wcefEngine = wcefField;
                else if (wcefField.getName().equals("engine_id"))
                    wcefEngineId = wcefField;
            }


            Method wcefSetValue = null;
            if(!noEnterpriseFieldType){
            for(Method m: wcEnterpriseField.getMethods())
                //System.out.println(m.getName());
                if(m.getName().trim().equals("setValue"))
                    wcefSetValue = m;
            }


            /*EAP Method*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefEap.get(selectedConfig), ENTERPRISE_EAP);
            }
            else
            {
                    wcefEap.set(selectedConfig, ENTERPRISE_EAP);
            }
            /*EAP Phase 2 Authentication*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefPhase2.get(selectedConfig), ENTERPRISE_PHASE2);
            }
            else
            {
                wcefPhase2.set(selectedConfig, ENTERPRISE_PHASE2);
            }
            /*EAP Anonymous Identity*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefAnonymousId.get(selectedConfig), ENTERPRISE_ANON_IDENT);
            }
            else
            {
                wcefAnonymousId.set(selectedConfig, ENTERPRISE_ANON_IDENT);
            }
            /*EAP CA Certificate*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefCaCert.get(selectedConfig), ENTERPRISE_CA_CERT);
            }
            else
            {
                wcefCaCert.set(selectedConfig, ENTERPRISE_CA_CERT);
            }               
            /*EAP Private key*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefPrivateKey.get(selectedConfig), ENTERPRISE_PRIV_KEY);
            }
            else
            {
                wcefPrivateKey.set(selectedConfig, ENTERPRISE_PRIV_KEY);
            }               
            /*EAP Identity*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefIdentity.get(selectedConfig), userName);
            }
            else
            {
                wcefIdentity.set(selectedConfig, userName);
            }               
            /*EAP Password*/
            if(!noEnterpriseFieldType)
            {
                    wcefSetValue.invoke(wcefPassword.get(selectedConfig), passString);
            }
            else
            {
                wcefPassword.set(selectedConfig, passString);
            }               
            /*EAp Client certificate*/
            if(!noEnterpriseFieldType)
            {
                wcefSetValue.invoke(wcefClientCert.get(selectedConfig), ENTERPRISE_CLIENT_CERT);
            }
            else
            {
                wcefClientCert.set(selectedConfig, ENTERPRISE_CLIENT_CERT);
            }
            /*Engine fields*/
            if(!noEnterpriseFieldType)
            {
            wcefSetValue.invoke(wcefEngine.get(wifiConf), "1");
            wcefSetValue.invoke(wcefEngineId.get(wifiConf), "keystore");
            }

            // Adhoc for CM6
            // if non-CM6 fails gracefully thanks to nested try-catch

            try{
            Field wcAdhoc = WifiConfiguration.class.getField("adhocSSID");
            Field wcAdhocFreq = WifiConfiguration.class.getField("frequency");
            //wcAdhoc.setBoolean(selectedConfig, prefs.getBoolean(PREF_ADHOC,
            //      false));
            wcAdhoc.setBoolean(selectedConfig, false);
            int freq = 2462;    // default to channel 11
            //int freq = Integer.parseInt(prefs.getString(PREF_ADHOC_FREQUENCY,
            //"2462"));     // default to channel 11
            //System.err.println(freq);
            wcAdhocFreq.setInt(selectedConfig, freq); 
            } catch (Exception e)
            {
                e.printStackTrace();
            }

        } catch (Exception e)
        {
            // TODO Auto-generated catch block
            // FIXME As above, what should I do here?
            e.printStackTrace();
        }

        return selectedConfig;
    }
}
