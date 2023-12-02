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
        "data:image/png;base64,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BogBggFigBggkpRMd/RsL19muL91kmFhgBggBggGiAFigEhSUreqP1UeIi/Pm2BgGCAGiAGCAWKAGCCSlEwrtjxWvlX90JxxhoYBYoAYIBggBogBIkkJ3ap+z8ODt6rPbjY4DBADxADBADFADBBJSugyw033DV1mmDE8DBADxADBADFADBBJSqYN67vjnYunGh8GiAFigGCAGCAGiCQle5nh3uy5BogBYoAYIBggBogBIklJ9Xx875plcW/bWQYIBogBggFigBggkpT0reqnGSAGiAECBogBYoBIUkK3qt8/eKv6wIJTDBADxAABA8QAMUAkKanLDLeVLzM80DrRADFADBAwQAwQA0SSkmn5lifKlxkenHuiAWKAGCBggBggBogkJXSZ4eZHBy8znNNigBggBggYIAaIASJJydS1qSfevuSzYYg0GSAGiAECBogBYoBIUkK3qt+1eehWdQPEADFAwAAxQAwQSUqojevXxLs6phggBogBAgaIAWKASFKyt6q/2H62AWKAGCBggBggBogkJX2Z4ekGiAFigIABYoAYIJKU0GWGDwxeZlhcMNkAMUAMEDBADBADRJKS6Y6e7eXLDPe3TjJADBADBAwQA8QAkaSkblV/qjxEXp43wQAxQAwQMEAMEANEkpJpxZbHyreqH5ozzgAxQAwQMEAMEANEkhK6Vf2ehwdvVZ/dbIAYIAYIGCAYIJKU0GWGm+4buswwY4AYIAYIBogBggEiScm0YX13vHPxVAPEADFAMEAMEAwQSUr2MsO92XMNEAPEAMEAMUAMEElSUj0f37tmWdzbdpYBYoAYIBggBogBIklK+lb10wwQA8QAwQAxQAwQSVJCt6rfP3ir+sCCUwwQA8QAwQAxQAwQSVJSlxluK19meKB1ogFigBggGCAGiAEiSUqm5VueKF9meHDuiQaIAWKAYIAYIAaIJCmhyww3Pzp4meGcFgPEADFAMEAMEANEkpRMXZt64u1LPhuGSJMBYoAYIBggBogBIklK6Fb1uzYP3apugBggBggGiAFigEiSEmrj+jXxro4pBogBYoBggBggBogkKdlb1V9sP9sAMUAMEAwQA8QAkSQlfZnh6QaIAWKAYIAYIAaIJCmhywwfGLzMsLhgsgFigBggGCAGiAEiSUqmO3q2ly8z3N86yQAxQAwQDBADxACRJCV1q/pT5SHy8rwJ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ifBfFb4RXuj/6o+dJEmqUAeastG94Xsd/7Oxo/+DpU9vOKlBCjR9o/juMEg+lclGreEzlmvCf3l41h9ESZI0wh1syhe+F84c3wpnjqvD//yD8C7HO53EgJ++SxIuOjxz8J6Rwhea8sWvlt4SDd0S/oDcHv733eF/v1GqnqLX0vpQD//h4B9T/H/3NP/q3/Ne96qy1+M/lM4I4W/S0nBOWBg+9v234X9+Ppwnpoxr2zc5jI23O2EBUD/v5IVfSUnrQbQlVzgntf93zxYWp3Z4ZqMlXvkAAAaIAWKAGCAAAAaIAWKAGCAAABggBogBYoAAABggBogBYoAAAGCAGCAGiAECAGCAGCAGiAECAGCAGCAGiAECAIABYoAYIAYIAIABYoAYIAYIAAAGiAFigBggAAAGiAFigBggAAAGiAFigBggAAAYIAaIAWKAAAAYIAaIAWKAAABggBggBogBAgBggBggBogBAgBggBggBogBAgCAAWKAGCAGCACAAWKAGCAGCAAABogBYoAYIAAABogBYoAYIAAAGCAGiAECAIABYoAYIAYIAIABYoAYIAYIAAAGiAFigBggAAAGiAFigBggAAAYIAaIAQIAgAFigBggBggAgAFigBggBggAAAaIAWKAGCAAAAaIAWKAGCAAABggBogBYoAAABggBogBYoAAABggBogBYoAAAGCAGCAGiAECAGCAGCAGiAECAIABYoAYIAYIAIABYoAYIAYIAIABYoAYIAYIAAAGiAFigBggAAAGiAFigBggAAAYIAaIAWKAAAAYIAaIAWKAAAAYIAaIAWKAAABggBggBogBAgBggBggBogBAgCAAWKAGCAGCACAAWKAGCAGCACAAWKAGCAGCAAABogBYoAYIAAABogBYoAYIAAAGCAGiAFigAAAGCAGiAFigAAAYIAYIAYIAAAGiAFigBggAAAGiAFigBggAAAYIAaIAWKAAAAYIAaIAWKAAABggBggBogBAgBggBggBogBAgBggBggBogBAgCAAWKAGCAGCACAAWKAGCAGCAAABogBYoAYIAAABogBYoAYIAAABogBYoAYIAAAGCAGiAFigAAAGCAGiAFigAAAYIAYIAaIAQIAYIAYIAaIAQIAYIAYIAaIAQIAgAFigBggBggAgAFigBggBggAAAaIAWKAGCAAAAaIAWKAGCAAAAaIAWKAGCAA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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAyAAAAMgCAYAAADbcAZoAAAABmJLR0QA/wD/AP+gvaeTAAAxwUlEQVR42u3deXSd5WHncUE2rCvJNsWxk7bgdDJhKe2UlELaGabHcXLaTDqTZJq0M0lPJ+zUToAY2pTxpPHBi2JjLN175QR1zDgQB8ISu14kbxgMtoBSIGnKkgabAQeMFyTrvlfY2AHeee6VnMnCItvSe5f38znnezqn82d99T4/7vI0NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEDSxn69f3xjbt9ZzdnoU5l84YqmbOHa0OKmXOE7Tbno9vA/N0qSJB2uOR91lc4Izbno5qZcsa0pW5wZ/ncXZjr6P9qyuPD+hlnxO52wgLLG/EvvbcoXP5PJRvPDH4z14Y/HzlAsSZI0gv0k9FhTvnBrGClfDp3XsCge4yQGKTC+s29sGBx/GgbHkkwuetofREmSVKEOhnrCueSrLbnCOeFdkuOd1KBOtCwqnFh6GzS8Hbph6L9A+KMnSZKqrT2hG8J5ZUrD7fHbnOCg1oT/ihC+v/FH4YX83dAhf9QkSVIN9Xxo7th8//sc6qDKnTR/b3P4eNUMH6+SJEl10Kvh+yJrM7mBjzjlQZUJXyCfMPhF8qjfHytJklR35QvfC98X+XPfFYEKK/1kbnhBzgkvzKI/TpIkKQX9IHy39ZMNcXyckyAkKbzoMrnCX4YX4W5/iCRJUurKRvc2dRR/06EQEtDcHp0aLv25yx8fSZKU8sIP7RSzExbvaXJChNHQubMx3Eg+a+h3s/3RkSRJKn8/JHqu9MkQh0UYQeGCng+FX4F4xh8ZSZKkN6p4S+kXQZ0c4Vi/65EvXOFdD0mSpGH1o0zbwO84RMJRGN/ZNza8iO7wh0SSJOmIern0H3CdJuFIPnLVXjg3vI34rD8gkiRJR1vhOxOv25VxsoS30NwR/UkYHy/5oyFJknRshe/QPlS6sNkJE95AeLvwLwZ/Us4fDEmSpBFq29hc/79x0oRfHh+lL5u/6o+EJEnSiLczkxv4d06cUBJ+6ao5H13nD4MkSdKo1tecjf7A4RPvfOSjef4gSJIkJVKhsaP/g06gpFZTvjjNHwJJkqRE2xN+9OcDTqKk752PXOG/+86HJElSBcpH2zOLByY5kZKe8ZEdmBr+8b/sD4AkSVLF+sG4tn3jnEyp/49dZYtnhn/wRS96SZKkSldc3zArPt4JlbpVuo0z/GN/3ItdkiSpWj6OVfyKUyp1K/zc7je90CVJkqqqV8MdIR9xUqX+xkcuusALXJIkqSrb5Uvp1Nf3PjqKvxk+Y/iSF7ckSVLVdnfD7fHbnFypfbPit4d/0N/3opYkSaruwjUJVzq8UvMy2WiGF7QkSVJNFI1ZtP9XnWCp3fERPksY/iH3ezFLkiTVyq9iFW51iqV2v/uRK9zmhSxJklRbNeYLH3OSpfbe/ejo/6gXsCRJUk32o4al8QlOtNTaF89/6MUrSZJUm4X72/7GoZaaEf7BXuiFK0mSVNO9OGHxniYnW6pfZ/yOTC562otWkiSptvOzvHj3Q5IkSUn2fEMufpcTLtUrjo8L/1Af92KVJEmqk/LFyxxyqVotucLHvVAlSZLq6WNY0f8tfcTeSZfq/PhVLur2QpUkSaq7d0H+1EmXqjMm23dy+Af6ihepJElSvVVc57RL1WnKFq714pQkSarLXh3Xtm+yEy/VNUBy0TYvTkmSpPqsORtd48RL1WhsL/yeF6YkSVI9fw+k8D2nXqrny+f56DovTEmSpDp/F6Qj+oCTL9Xy8asfelFKkiTVd5lsNMPJl4obm+9/nxekJElSGipsdPqlCt79KP6VF6MkSVIqennidbsyTsBUeIAUbvNilCRJSsnHsHIDH3ECptLf//ixF6MkSVJafg2r+FUnYCpm6PZzL0RJkqS0lC1ucAqmYsKFNJ/yQpQkSUpVvU7BVO7jV+EtOC9CSZKkdNWYf+m9TsJUZoBkozu9CCVJklL2RfRs4Y+dhKnUF9B/4EUoSZKUtu+BFL7oJEylBkjkRShJkpSuwveAFzkJk/wX0BdGJ3kBSpIkpbIVTsMkLtM+8NtefJIkSSl8ByQXPeQ0TCV+AevDXoCSJEkpLB9tdxqmAr+AVfwzL0BJkqRUVnAaJvnvgGSji7z4JEmS0lnDrPh4J2KSfgdkuhefJElSSgfI0vgEJ2KS/RJ6vvAlLz5JkqR0Nr6zb6wTMYlqaS+cG34B4cuSJElpLJOP5qV7hBQnOBEDAEBCxize/+upHiDfKL7bvwIAADBADBAAADBADBAAAMAAMUAAAMAAMUAAAAADxAABAAADxAABAAADxAABAAAMEAMEAAAMEAMEAAAwQAwQAAAwQAwQAAAwQAwQAADAADFAAADAADFAAAAAA8QAAQAAA8QAAQAAA8QAAQAADBADBAAADBADBAAAMEAMEAAAMEAMEAAAMEAMEAAAwAAxQAAAwAAxQAAAAAPEAAEAAAPEAAEAAAPEAAEAAAwQAwQAAAwQAwQAADBADBAAADBADBAAAMAAMUAAAMAAMUAAAMAAMUAAAAADxAABAAADxAABAAAMEAMEAAAMEAMEAAAMEAMEAAAwQAwQAAAwQAwQAADAADFAAADAADFAAADAADFAAAAAA8QAAQAAA8QAAQAADBADBAAADBADBAAADBADBAAAMEAMEAAAMEAMEAAAwAAxQAAAwAAxQAAAwAAxQAAAAAPEAAEAAAPEAAEAAAwQAwQAAAwQAwQAADBADBAAADBADBAAADBADBAAAMAAMUAAAMAAMUAAAAADxAABAAADxAABAAADxACBkbM0PmHs1/vHp7GT5u9t9g/g57Xdt/c9s+7a/RuSpPot1/1UiyeeAWKAUDHNuejL6X3RFe7yL+AX9uj9u/75K5t64wu6o/h8SVJddfXqp+Oeb14VP7n04ls98QwQAwQDxACpCt95cOc/heIbe3bFMzf1xeev9cCWpFrvi10vxBtvnh0fmDchfmV2Y/z0jZ+7zRPPADFAMEAMkKoaIIdbsnVXfM1dfR7gklSDTevaXR4e+1snlYfH4QwQA8QAwQAxQKp2gBzuhq274xkb93mgS1INdHFXb/wP387FxfmTf254GCAGiAGCAWKA1MwAOdzirXviKzYYIpJUjV2wtj/+9m03x33Xn/G6w8MAMUAMEAwQA6TmBki5B3bG7fftiaev6/fAl6Qq6YY7VsV72s5+0+FhgBggBggGiAFSmwNkqFtDC+/dG1+21hCRpErVvnxj/FxuyrCGhwFigBggGCAGSE0PkMN9O7wj0rr5xfiStQWHAUlKqNYVD8Y/vOEzRzQ8DBADxADBADFA6mKAHG7Z0BC52E/3StKode3KR+LHOj8X/2RO01GNDwPEADFAMEAMkLoZIIe7+YEX4mvvfjG+sNs7IpI0Ul2z6sn4e0suCsOj5aiHhwFigBggGCAGSF0OkMMt7Xkhdqu6JB1bM1Y/U769/ODcE495eBggBogBggFigNT1APnpZYY9g5cZGiKSNPymrx66vbx14ogNDwPEADFAMEAMkFQMkMN1hlvVr3KZoSS9aZd27y1fIjgw/+QRHx4GiAFigGCAGCCpGiA/f5mhn+6VpNe7RLB/4amjNjwMEAPEAMEAMUBSOUAO3yGS27Invny9ISIp3ZV+sKM0PHoXnjnqw8MAMUAMEAwQAyS1A+QXb1Wfts4vZklK5+3lu9vPSWx4GCAGiAGCAWKAGCBD3RJ+urd0q/qlhoikFLRo+d3xjvzUxIeHAWKAGCAYIAaIAfIGt6q7zFBSPTZ35UNDt5dnKjY+DBADxADBADFADJA3uczworXeEZFU+81c9fjgJYKzmys6PAwQA8QAwQAxQAyQt+im+3e5zFBSzXb16qfLlwgemjOuKoaHAWKAGCAYIAaIATLMbgyXGc7c1Bef76NZkmqgK9fsiDffNDM+MG9CVQ0PA8QAMUAwQAwQA+RIb1XfOnirugOOpGpsWtfu8u3l+1snVeXwMEAMEAMEA8QAMUCOshu27o5nuFVdUpV0cVdv+fby4vzJVT08DBADxADBADFADJARuVXdEJFU2dvL+64/oyaGhwFigBggGCAGiAEygpcZTl/nVnVJyV4iuKft7JoaHgaIAWKAYIAYIAbICHZrqHSZ4WVrDRFJo1f78o3xc7kpNTk8DBADxADBADFADJBRvMzwEneISBrBWlc8OHSJYGPNZ4AYIAYIBogBYoCMQsvcqi5pBLp25SNVcXu5AWKAGCAYIAaIAVIjHb5V/cJu74hIGn7XrHpy8PbyOS11MzwMEAPEAMEAMUAMkARb2vOCW9UlvWUzVj9Tvr384NzxdTc8DBADxADBADFADJBKXGbYM3iZoSEi6WebvvqF8iWCB1on1u3wMEAMEAMEA8QAMUAqWGe4Vf0qlxlKqe/S7r3lSwQH5p9c98PDADFADBAMEAPEAKmaywz9dK+U1ksE+xeemprhYYAYIAYIBogBYoBU0R0iuS174svXGyJSvVf6QYrS8OhdeGbqhocBYoAYIBggBogBUqW3qk9b5xezpHq9vXx3+zmpHR4GiAFigGCAGCAGSJV2S/jp3tKt6pcaIlJdtGj53fGO/NTUDw8DxAAxQDBADBADpEZuVXeZoVSbzV35UN1dImiAGCAGCAaIAWKApKDDlxletNY7IlItNHPV44OXCM5uNjgMEAPEAMEAMUAMkNrtpvt3ucxQquKuXv10+RLBQ3PGGRoGiAFigGCAGCAGSP10Y7jMcOamvvh8H82SqqIr1+yIN980Mz4wb4KBYYAYIAYIBogBYoDU8a3qWwdvVXcAlCrTtK7d5dvL97dOMiwMEAPEAMEAMUAMkPR0w9bd8Qy3qkuJdXFXb/n28uL8yQaFAWKAGCAYIAaIAZLeSreqX77eEJFG+/byvuvPMCQMEAPEAMEAMUAMEP3sZYbT17lVXRrpSwT3tJ1tQBggBogBggFigBgger1uDZUuM7xsrSEiHUu5726In8tNMRwMEAPEAMEAMUAMEB3JZYaXuENEOqJaVzw4dImgwWCAGCAGCAaIAWKA6Ihb5lZ1aVhdu/IRt5cbIAaIAYIBYoAYIBrpW9Uv7PaOiPSzXbPqycHby+e0GAkGiAFigGCAGCAGiEa6pT0vuFVdCs1Y/Uz59vKDc8cbBwaIAWKAYIAYIAaIRv0yw57BywwNEaWt6atfKF8ieKB1olFggBggBggGiAFigCjpOsOt6le5zFAp6NLuveVLBAfmn2wMGCAGiAGCAWKAGCAGSDVcZnjFBj/dq/q9RLB/4alGgAFigBggGCAGCAZItd0hkttSulXdEFHtV/rBhdLw6F14psO/AWKAGCBggPgXYIDUwq3q09b5xSzV7u3lu9vPceg3QAwQAwQMEAPEAKmlbgk/3Vu6Vf1SQ0Q10qLld8c78lMd9g0QA8QAAQPEADFA6uFWdZcZqlqbu/IhlwgaIAaIAQIGiAFigNTrZYYXrfWOiKqjmaseH7xEcHazA74BYoAYIGCAGCAGSL120/27XGaoinb16qfLlwgemjPOwd4AMUAMEDBADBADJC3dGC4znLmpLz7fR7OUUFeu2RFvvmlmfGDeBAd6A8QAMUDAADFADJDU3qq+dfBWdQdkjVbTunaXby/f3zrJQd4AMUAMEDBADBADRIPdsHV3fNUGt6pr5Lq4q7d8e3lx/mQHeAPEADFAwAAxQAwQvfGt6pevN0R07LeX911/hoO7AWKAGCBggBggBoiGf5nh9HVuVdeRXyK4p+1sB3YDxAAxQMAAMUAMEB15t4ZKlxlettYQ0ZuX++6G+LncFAd1A8QAMUDAADFADBCN3GWGl7hDRL9Q64oHhy4RdEA3QAwQAwQMEAPEANEIt8yt6hrq2pWPuL3cADFADBAwQAwQA0TJ3qp+Ybd3RNLWNaueHLy9fE6LQ7kBYoAYIGCAGCAGiJJtac8LblVPSTNWP1O+vfzg3PEO4wYIBogBggFigBggqvBlhj2DlxkaIvXX9NUvlC8RPNA60SHcADFADBADBAPEADFAVF11hlvVr9roDpF66NLuveVLBAfmn+zwLQPEADFAMEAMEANE1X+Z4RUb/HRvLV8i2L/wVIduGSAGiAGCAWKAGCCqrTtEcltKt6obIrVQ6QcFSsOjd+GZDtsyQAwQAwQDxAAxQFT7t6pPW+8Xs6r59vLd7ec4ZMsAMUAMEAwQA8QAUf10S/jp3vKt6usMkWqpbfmmeEfHhx2uZYAYIAYIBogBYoCo/m9Vd5lh5Zq78iGXCMoAMUAMEAwQA8QAUTovM7xorXdEkmrmqscHLxGc3exALQPEADFAMEAMEANE6eym+3e5zHCUu3r10+VLBA/NGecgLQPEADFAMEAMEANEKnVjuMxw5qa++HwfzRqxrlyzI95808z4wLwJDtAyQAwQAwQDxAAxQKTXvVV96+Ct6gbE0Teta3f59vL9rZMcnGWAGCAGCAaIAWKASMPphq2746s2uFX9SLq4q7d8e3lx/mQHZhkgBogBggFigBgg0tHeqn75ekNkOLeX911/hoOyDBADxADBADFADBBppC4znL7Oreqvd4ngnrazHZBlgBggBggGiAFigEgj3a2h8mWGaw2R3Hc3xM/lpjgYywAxQAwQDBADxACRkrrM8JIU3iHSuuLBoUsEHYhlgBggBggGiAFigEiJtixFt6pfu/IRt5fLADFADBAMEAMEA0TVdKv6hd31947INaueHLy9fE6LQ7AMEAPEAMEAMUAwQFRNLe15oW5uVZ+x+pny7eUH5453+JUBYoAYIGCAYICo2m9VL11mWItDZPrqF8qXCB5onejQKwPEADFAwAAxQAwQ1VKd4Vb1qzbWxh0il3bvLV8iODD/ZIddGSAGiAECBogBYoCo1i8zvGJDf1VfIti/8FSHXBkgBogBAgaIAWKAqJ7uEMlt2RN/sUpuVS99Yb40PHoXnulwKwPEADFAwAAxQAwQ1fut6tPWFyp6e/nu9nMcamWAGCAGCBggBogBorR0S/jp3vKt6uuSGyJtyzfFOzo+7DArA8QAMUDAADFADBCl/Vb10bzMcO7Kh1wiKAPEADFAwAAxQAwQ6ZcvM7xo7ci9IzJz1eODlwjObnaAlQFigBggYIAYIAaI9MvddP+uY77M8OrVT5cvETw0Z5yDqwwQA8QAAQPEADFApOFdZjhzU198/hF8NOvKNTvizTfNjA/Mm+DAKgPEADFAwAAxQAwQ6chbsnXwVvU3Gx7TunaXby/f3zrJQVUGiAFigIABYoAYINKxd8PW3fFVG37+DpGLu3rLt5cX5092QJUBYoAYIGCAGCAGiDTylS4zvGJ9b3zL7TfHfdef4WAqA8QAMUDAADFADBBpdLvtgefirSuXxP3Xn+5gKgPEADFAwAAxQAwQKZluf+DZ+KE7F8XFBT6CJQPEADFAwAAxQAwQKaHu6Nkef/87s3wJXQaIAWKAgAFigBggUnLd2fNUeYgcaH23A6sMEAPEAAEDxAAxQKRkWnHf4/Fj37rSRYQyQAwQAwQMEAPEAJGSa9U9D8c/WnpB/JPZzQ6wMkAMEAMEDBADxACRkql705b4mb//dDjEZRxkZYAYIAYIGCAGiAEiJdOG9d3xzsVTHWZlgBggBggYIAaIASIl193dd8Z7s+c61MoAMUAMEDBADBADREqq5+N71yyLe9vOcriVAWKAGCBggBggBoiU9K3qpznkygAxQAwQMEAMEANESuhW9fsHb1UfWHCKw64MEAPEAAEDxAAxQKSkLjPcNnSZ4USHXhkgBogBAgaIAWKASMm0fMsT5csMD8490eFXBogBYoCAAYIBIiV0meHmRwcvM5zT4hAsA8QAMUAwQAwQDBApmbo29cTbl3w2DJEmh2EZIAaIAYIBYoAYIA6IUkK3qt+1eehWdQdiGSAGiAGCAWKAGCCSEmrj+jXxro4pDsYyQAwQAwQDxAAxQCQle6v6i+1nOyDLADFADBAMEAPEAJGU9GWGpzsoywAxQAwQDBADxACRlNBlhg8MXmZYXDDZgVkGiAFigGCAGCAGiKRkuqNne/kyw/2tkxycZYAYIAYIBogBYoBISupW9aeGblV/twO0DBADxADBADFADBBJybTivsfLt6ofmjPOQVoGiAFigGCAGCAGiKSEblW/5+HBW9VnNztQywAxQAwQDBADxACRlNBlhpu2DF1mmHGwlgFigBggGCAGiAEiKZk2rO+Ody6e6nAtA8QAMUAwQAwQA0RSspcZ7s2e65AtA8QAMUAwQAwQA0RSUj0f37tmWdzbdpbDtgwQA8QAwQAxQAwQSUnfqn6aQ7cMEAPEAMEAMUAMEEkJ3ap+/+Ct6gMLTnH4lgFigBggGCAGiAEiKanLDLcNXWY40SHcADFADBADBAPEADFAJCXT8i1PlC8zPDj3RIdxAwQDxADBADFADBBJCV1muPnRwcsM57Q4lBsgBogBAgaIAWKASEqmrk098fYlnw1DpMnh3AAxQAwQMEAMEANEUkK3qt+1eehWdQd0A8QAMUDAADFADBBJCbVx/Zp4V8cUB3UDxAAxQMAAMUAMEEnJ3qr+YvvZDuwGiAFigIABYoAYIJKSvszwdAd3A8QAMUDAADFADBBJCV1m+MDgZYbFBZMd4A0QA8QAAQPEADFAJCXTHT3by5cZ7m+d5CBvgBggBggYIAaIASIpqVvVnyoPkZfnTXCgN0AMEAMEDBADxACRlEwrtjxWvlX90JxxDvYGiAFigIABYoAYIJISulX9nocHb1Wf3eyAb4AYIAYIGCAGiAEiKaHLDDdtGbrMMOOgb4AYIAYIGCAGiAEiKZk2rO+Ody6e6rBvgBggBggYIAaIASIp2csM92bPdeg3QAwQAwQMEAPEAJGUVM/H965ZFve2neXwb4AYIAYIGCD+BRggkpK+Vf00I8AAMUAMEAwQAwQDRFJCt6rfP3ir+sCCU4wBA8QAMUAwQAwQA8QAkZTUZYbbypcZHmidaBQYIAaIAYIBYoAYIJKUTMu3PFG+zPDg3BONAwPEADFAMEAMEANEkhK6zHDzo4OXGc5pMRIMEAPEAMEAMUAMEElKpq5NPfH2JZ8NQ6TJWDBADBADBAPEADFAJCmhW9Xv2jx0q7rBYIAYIAYIBogBYoBIUkJtXL8m3tUxxXAwQAwQAwQDxAAxQCQp2VvVX2w/24AwQAwQAwQDxAAxQCQp6csMTzckDBADxADBADFADBBJSugywwcGLzMsLphsUBggBogBggFigBggkpRMd/RsL19muL91kmFhgBggBggGiAFigEhSUreqP1UeIi/Pm2BgGCAGiAGCAWKAGCCSlEwrtjxWvlX90JxxhoYBYoAYIBggBogBIkkJ3ap+z8ODt6rPbjY4DBADxADBADFADBBJSugyw033DV1mmDE8DBADxADBADFADBBJSqYN67vjnYunGh8GiAFigGCAGCAGiCQle5nh3uy5BogBYoAYIBggBogBIklJ9Xx875plcW/bWQYIBogBggFigBggkpT0reqnGSAGiAECBogBYoBIUkK3qt8/eKv6wIJTDBADxAABA8QAMUAkKanLDLeVLzM80DrRADFADBAwQAwQA0SSkmn5lifKlxkenHuiAWKAGCBggBggBogkJXSZ4eZHBy8znNNigBggBggYIAaIASJJydS1qSfevuSzYYg0GSAGiAECBogBYoBIUkK3qt+1eehWdQPEADFAwAAxQAwQSUqojevXxLs6phggBogBAgaIAWKASFKyt6q/2H62AWKAGCBggBggBogkJX2Z4ekGiAFigIABYoAYIJKU0GWGDwxeZlhcMNkAMUAMEDBADBADRJKS6Y6e7eXLDPe3TjJADBADBAwQA8QAkaSkblV/qjxEXp43wQAxQAwQMEAMEANEkpJpxZbHyreqH5ozzgAxQAwQMEAMEANEkhK6Vf2ehwdvVZ/dbIAYIAYIGCAYIJKU0GWGm+4buswwY4AYIAYIBogBggEiScm0YX13vHPxVAPEADFAMEAMEAwQSUr2MsO92XMNEAPEAMEAMUAMEElSUj0f37tmWdzbdpYBYoAYIBggBogBIklK+lb10wwQA8QAwQAxQAwQSVJCt6rfP3ir+sCCUwwQA8QAwQAxQAwQSVJSlxluK19meKB1ogFigBggGCAGiAEiSUqm5VueKF9meHDuiQaIAWKAYIAYIAaIJCmhyww3Pzp4meGcFgPEADFAMEAMEANEkpRMXZt64u1LPhuGSJMBYoAYIBggBogBIklK6Fb1uzYP3apugBggBggGiAFigEiSEmrj+jXxro4pBogBYoBggBggBogkKdlb1V9sP9sAMUAMEAwQA8QAkSQlfZnh6QaIAWKAYIAYIAaIJCmhywwfGLzMsLhgsgFigBggGCAGiAEiSUqmO3q2ly8z3N86yQAxQAwQDBADxACRJCV1q/pT5SHy8rwJ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ifBfFb4RXuj/6o+dJEmqUAeastG94Xsd/7Oxo/+DpU9vOKlBCjR9o/juMEg+lclGreEzlmvCf3l41h9ESZI0wh1syhe+F84c3wpnjqvD//yD8C7HO53EgJ++SxIuOjxz8J6Rwhea8sWvlt4SDd0S/oDcHv733eF/v1GqnqLX0vpQD//h4B9T/H/3NP/q3/Ne96qy1+M/lM4I4W/S0nBOWBg+9v234X9+Ppwnpoxr2zc5jI23O2EBUD/v5IVfSUnrQbQlVzgntf93zxYWp3Z4ZqMlXvkAAAaIAWKAGCAAAAaIAWKAGCAAABggBogBYoAAABggBogBYoAAAGCAGCAGiAECAGCAGCAGiAECAGCAGCAGiAECAIABYoAYIAYIAIABYoAYIAYIAAAGiAFigBggAAAGiAFigBggAAAGiAFigBggAAAYIAaIAWKAAAAYIAaIAWKAAABggBggBogBAgBggBggBogBAgBggBggBogBAgCAAWKAGCAGCACAAWKAGCAGCAAABogBYoAYIAAABogBYoAYIAAAGCAGiAECAIABYoAYIAYIAIABYoAYIAYIAAAGiAFigBggAAAGiAFigBggAAAYIAaIAQIAgAFigBggBggAgAFigBggBggAAAaIAWKAGCAAAAaIAWKAGCAAABggBogBYoAAABggBogBYoAAABggBogBYoAAAGCAGCAGiAECAGCAGCAGiAECAIABYoAYIAYIAIABYoAYIAYIAIABYoAYIAYIAAAGiAFigBggAAAGiAFigBggAAAYIAaIAWKAAAAYIAaIAWKAAAAYIAaIAWKAAABggBggBogBAgBggBggBogBAgCAAWKAGCAGCACAAWKAGCAGCACAAWKAGCAGCAAABogBYoAYIAAABogBYoAYIAAAGCAGiAFigAAAGCAGiAFigAAAYIAYIAYIAAAGiAFigBggAAAGiAFigBggAAAYIAaIAWKAAAAYIAaIAWKAAABggBggBogBAgBggBggBogBAgBggBggBogBAgCAAWKAGCAGCACAAWKAGCAGCAAABogBYoAYIAAABogBYoAYIAAABogBYoAYIAAAGCAGiAFigAAAGCAGiAFigAAAYIAYIAaIAQIAYIAYIAaIAQIAYIAYIAaIAQIAgAFigBggBggAgAFigBggBggAAAaIAWKAGCAAAAaIAWKAGCAAAAaIAWKAGCAA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".into()
    }
}
