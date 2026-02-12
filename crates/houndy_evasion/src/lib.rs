pub mod syscalls;
pub mod unhook;

pub fn init() {
    #[cfg(target_os = "windows")]
    unsafe {
        if unhook::refresh_ntdll() {
            log::info!("ntdll.dll unhooked successfully");
        } else {
            log::warn!("Failed to unhook ntdll.dll");
        }
    }
}
