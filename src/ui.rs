use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
